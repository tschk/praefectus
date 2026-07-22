use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr;

use windows::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GENERIC_ALL, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GetSecurityInfo, SE_FILE_OBJECT, SET_ACCESS,
    SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_FLAGS, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
    GetSecurityDescriptorControl, GetSecurityDescriptorLength, GetTokenInformation,
    INHERIT_ONLY_ACE, IsValidAcl, IsValidSecurityDescriptor, IsValidSid, IsWellKnownSid,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
    FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FileRenameInfo, GetFileInformationByHandle, OPEN_EXISTING, READ_CONTROL,
    SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PWSTR, w};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub(crate) struct PathGuard {
    _handles: Vec<OwnedHandle>,
}

impl PathGuard {
    pub(crate) fn lock(path: &Path) -> io::Result<Self> {
        let absolute = absolute_path(path)?;
        let user = CurrentUser::load()?;
        let mut candidates = absolute.ancestors().collect::<Vec<_>>();
        candidates.reverse();
        let mut handles = Vec::with_capacity(candidates.len());
        for (index, candidate) in candidates.iter().enumerate() {
            if candidate.as_os_str().is_empty() {
                continue;
            }
            match open_path(
                candidate,
                FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0,
                (index + 1 < candidates.len()).then_some(true),
            ) {
                Ok(handle) => {
                    validate_handle(handle.0, &user, false)?;
                    handles.push(handle);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            }
        }
        Ok(Self { _handles: handles })
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

struct CurrentUser {
    _storage: Vec<usize>,
    sid: PSID,
    _trusted_installer: LocalAllocation,
    trusted_installer_sid: PSID,
}

impl CurrentUser {
    fn load() -> io::Result<Self> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(windows_error)?;
        let token = OwnedHandle(token);
        let mut length = 0u32;
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut length) };
        if length < std::mem::size_of::<TOKEN_USER>() as u32 {
            return Err(permission_error());
        }
        let words = usize::try_from(length)
            .ok()
            .and_then(|length| {
                length
                    .checked_add(std::mem::size_of::<usize>() - 1)
                    .map(|length| length / std::mem::size_of::<usize>())
            })
            .ok_or_else(permission_error)?;
        let mut storage = vec![0usize; words];
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                length,
                &mut length,
            )
        }
        .map_err(windows_error)?;
        let storage_bytes = storage
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or_else(permission_error)?;
        if usize::try_from(length).map_or(true, |length| length > storage_bytes) {
            return Err(permission_error());
        }
        let user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
        if !bounded_valid_sid(
            user.User.Sid,
            storage.as_ptr().cast(),
            usize::try_from(length).map_err(|_| permission_error())?,
        ) {
            return Err(permission_error());
        }
        let mut trusted_installer_sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(
                w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
                &mut trusted_installer_sid,
            )
        }
        .map_err(windows_error)?;
        let trusted_installer = LocalAllocation(trusted_installer_sid.0);
        if trusted_installer_sid.0.is_null()
            || !unsafe { IsValidSid(trusted_installer_sid) }.as_bool()
        {
            return Err(permission_error());
        }
        Ok(Self {
            sid: user.User.Sid,
            _storage: storage,
            _trusted_installer: trusted_installer,
            trusted_installer_sid,
        })
    }
}

pub(crate) fn available() -> bool {
    initialize_managed_state().is_ok()
}

fn initialize_managed_state() -> io::Result<()> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(permission_error)?;
    let _guard = PathGuard::lock(&local)?;
    validate_directory(&local, false)?;
    let managed = local.join("praefectus");
    match std::fs::create_dir(&managed) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    restrict_directory(&managed)
}

pub(crate) fn restrict_file(file: &File) -> io::Result<()> {
    let handle = HANDLE(file.as_raw_handle());
    validate_file_handle(handle, Some(false))?;
    let user = CurrentUser::load()?;
    let acl = owner_acl(&user, false)?;
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl.0.cast()),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(permission_error());
    }
    validate_handle(handle, &user, true)
}

pub(crate) fn restrict_directory(path: &Path) -> io::Result<()> {
    let _guard = PathGuard::lock(path)?;
    let user = CurrentUser::load()?;
    let acl = owner_acl(&user, true)?;
    let handle = open_path(
        path,
        FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | WRITE_DAC.0,
        Some(true),
    )?;
    let status = unsafe {
        SetSecurityInfo(
            handle.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl.0.cast()),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(permission_error());
    }
    validate_handle(handle.0, &user, true)
}

pub(crate) fn validate_directory(path: &Path, strict: bool) -> io::Result<()> {
    let _guard = PathGuard::lock(path)?;
    let user = CurrentUser::load()?;
    let handle = open_path(path, FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0, Some(true))?;
    validate_handle(handle.0, &user, strict)
}

pub(crate) fn lock_path(path: &Path) -> io::Result<PathGuard> {
    PathGuard::lock(path)
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    let _guard = PathGuard::lock(path)?;
    let handle = open_path(path, FILE_READ_ATTRIBUTES.0, Some(true))?;
    drop(handle);
    let anchor = path.join(".praefectus-durability");
    let open = |create_new| {
        let mut options = OpenOptions::new();
        options
            .create_new(create_new)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_WRITE_THROUGH.0);
        options.open(&anchor)
    };
    let mut file = match open(true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open(false)?,
        Err(error) => return Err(error),
    };
    restrict_file(&file)?;
    file.set_len(0)?;
    file.write_all(b"1")?;
    file.sync_all()
}

fn owner_acl(user: &CurrentUser, directory: bool) -> io::Result<LocalAllocation> {
    let inheritance = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        ACE_FLAGS(0)
    };
    let access = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS.0,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(user.sid.0.cast()),
            ..Default::default()
        },
    };
    let mut acl = ptr::null_mut::<ACL>();
    let status = unsafe { SetEntriesInAclW(Some(&[access]), None, &mut acl) };
    if status != ERROR_SUCCESS || acl.is_null() {
        return Err(permission_error());
    }
    Ok(LocalAllocation(acl.cast()))
}

fn validate_handle(handle: HANDLE, user: &CurrentUser, strict: bool) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut acl = ptr::null_mut::<ACL>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut acl),
            None,
            Some(&mut descriptor),
        )
    };
    if status != ERROR_SUCCESS || descriptor.0.is_null() {
        return Err(permission_error());
    }
    let allocation = LocalAllocation(descriptor.0);
    let result = validate_descriptor(owner, acl, allocation.0, user, strict);
    drop(allocation);
    result
}

fn validate_descriptor(
    owner: PSID,
    acl: *mut ACL,
    descriptor: *mut c_void,
    user: &CurrentUser,
    strict: bool,
) -> io::Result<()> {
    if descriptor.is_null()
        || !unsafe { IsValidSecurityDescriptor(PSECURITY_DESCRIPTOR(descriptor)) }.as_bool()
    {
        return Err(permission_error());
    }
    let descriptor_len =
        usize::try_from(unsafe { GetSecurityDescriptorLength(PSECURITY_DESCRIPTOR(descriptor)) })
            .map_err(|_| permission_error())?;
    if descriptor_len < std::mem::size_of::<windows::Win32::Security::SECURITY_DESCRIPTOR>()
        || !bounded_valid_sid(owner, descriptor.cast(), descriptor_len)
        || !unsafe { IsValidSid(user.sid) }.as_bool()
        || !bounded_acl(acl, descriptor.cast(), descriptor_len)
    {
        return Err(permission_error());
    }
    let owner_is_user = unsafe { EqualSid(owner, user.sid) }.is_ok();
    if strict && !owner_is_user || !strict && !trusted_principal(owner, user) {
        return Err(permission_error());
    }
    if !strict {
        return validate_ancestor_acl(acl, descriptor.cast(), descriptor_len, user, owner_is_user);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    unsafe {
        GetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(descriptor),
            &mut control,
            &mut revision,
        )
    }
    .map_err(windows_error)?;
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            acl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(windows_error)?;
    if control & SE_DACL_PROTECTED.0 == 0
        || acl_info.AceCount != 1
        || acl_info.AclBytesInUse < std::mem::size_of::<ACL>() as u32
    {
        return Err(permission_error());
    }
    let mut raw_ace = ptr::null_mut();
    unsafe { GetAce(acl, 0, &mut raw_ace) }.map_err(windows_error)?;
    if raw_ace.is_null() {
        return Err(permission_error());
    }
    let acl_start = acl.cast::<u8>() as usize;
    let ace_start = raw_ace.cast::<u8>() as usize;
    let acl_len = usize::try_from(acl_info.AclBytesInUse).map_err(|_| permission_error())?;
    if !range_contains(descriptor.cast(), descriptor_len, acl.cast(), acl_len) {
        return Err(permission_error());
    }
    let ace_offset = ace_start
        .checked_sub(acl_start)
        .filter(|offset| {
            offset
                .checked_add(std::mem::size_of::<ACE_HEADER>())
                .is_some_and(|end| end <= acl_len)
        })
        .ok_or_else(permission_error)?;
    let header = unsafe { ptr::read_unaligned(raw_ace.cast::<ACE_HEADER>()) };
    let ace_len = usize::from(header.AceSize);
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if ace_len < sid_offset + 8
        || ace_offset
            .checked_add(ace_len)
            .is_none_or(|end| end > acl_len)
    {
        return Err(permission_error());
    }
    let ace = unsafe { ptr::read_unaligned(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
    let sid = PSID(unsafe { raw_ace.cast::<u8>().add(sid_offset).cast() });
    if u32::from(ace.Header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || ace.Mask & FILE_ALL_ACCESS.0 != FILE_ALL_ACCESS.0
        || !bounded_valid_sid(sid, raw_ace.cast(), ace_len)
        || unsafe { EqualSid(sid, user.sid) }.is_err()
    {
        return Err(permission_error());
    }
    Ok(())
}

fn validate_ancestor_acl(
    acl: *mut ACL,
    descriptor: *const u8,
    descriptor_len: usize,
    user: &CurrentUser,
    owner_is_user: bool,
) -> io::Result<()> {
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            acl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(windows_error)?;
    let acl_len = usize::try_from(acl_info.AclBytesInUse).map_err(|_| permission_error())?;
    if acl_len < std::mem::size_of::<ACL>()
        || !range_contains(descriptor, descriptor_len, acl.cast(), acl_len)
    {
        return Err(permission_error());
    }
    for index in 0..acl_info.AceCount {
        let mut raw_ace = ptr::null_mut();
        unsafe { GetAce(acl, index, &mut raw_ace) }.map_err(windows_error)?;
        let (header, mask, sid) = bounded_ace(raw_ace, acl.cast(), acl_len)?;
        let ace_type = u32::from(header.AceType);
        if ace_type != ACCESS_ALLOWED_ACE_TYPE && ace_type != ACCESS_DENIED_ACE_TYPE {
            return Err(permission_error());
        }
        if ace_type == ACCESS_ALLOWED_ACE_TYPE
            && u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 == 0
            && ancestor_access_can_replace(mask, owner_is_user)
            && !trusted_principal(sid, user)
        {
            return Err(permission_error());
        }
    }
    Ok(())
}

fn bounded_ace(
    raw_ace: *mut c_void,
    acl: *const u8,
    acl_len: usize,
) -> io::Result<(ACE_HEADER, u32, PSID)> {
    if raw_ace.is_null()
        || !range_contains(
            acl,
            acl_len,
            raw_ace.cast(),
            std::mem::size_of::<ACE_HEADER>(),
        )
    {
        return Err(permission_error());
    }
    let header = unsafe { ptr::read_unaligned(raw_ace.cast::<ACE_HEADER>()) };
    let ace_len = usize::from(header.AceSize);
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if ace_len < sid_offset + 8 || !range_contains(acl, acl_len, raw_ace.cast(), ace_len) {
        return Err(permission_error());
    }
    let ace = unsafe { ptr::read_unaligned(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
    let sid = PSID(unsafe { raw_ace.cast::<u8>().add(sid_offset).cast() });
    if !bounded_valid_sid(sid, raw_ace.cast(), ace_len) {
        return Err(permission_error());
    }
    Ok((header, ace.Mask, sid))
}

fn ancestor_access_can_replace(mask: u32, owner_is_user: bool) -> bool {
    let destructive = DELETE.0 | FILE_DELETE_CHILD.0 | WRITE_DAC.0 | WRITE_OWNER.0 | GENERIC_ALL.0;
    let create = FILE_ADD_FILE.0 | FILE_ADD_SUBDIRECTORY.0 | GENERIC_WRITE.0;
    mask & destructive != 0 || owner_is_user && mask & create != 0
}

fn trusted_principal(sid: PSID, user: &CurrentUser) -> bool {
    unsafe { EqualSid(sid, user.sid) }.is_ok()
        || unsafe { IsWellKnownSid(sid, WinLocalSystemSid) }.as_bool()
        || unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) }.as_bool()
        || unsafe { EqualSid(sid, user.trusted_installer_sid) }.is_ok()
}

pub(crate) fn replace_file_durable(source: &Path, destination: &Path) -> io::Result<()> {
    let parent = destination.parent().ok_or_else(permission_error)?;
    let _source_parent = PathGuard::lock(source.parent().ok_or_else(permission_error)?)?;
    let _destination_parent = PathGuard::lock(parent)?;
    let source = open_path_shared(
        source,
        DELETE.0 | FILE_READ_ATTRIBUTES.0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        Some(false),
    )?;
    let destination = wide_path(&absolute_path(destination)?)?;
    let name = &destination[..destination.len() - 1];
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(permission_error)?;
    let buffer_len = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name.len().checked_mul(2).ok_or_else(permission_error)?)
        .ok_or_else(permission_error)?;
    let words = buffer_len
        .checked_add(std::mem::size_of::<usize>() - 1)
        .map(|length| length / std::mem::size_of::<usize>())
        .ok_or_else(permission_error)?;
    let mut buffer = vec![0usize; words];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*rename).Anonymous.ReplaceIfExists = true;
        (*rename).RootDirectory = HANDLE::default();
        (*rename).FileNameLength = name_bytes;
        ptr::copy_nonoverlapping(name.as_ptr(), (*rename).FileName.as_mut_ptr(), name.len());
        SetFileInformationByHandle(
            source.0,
            FileRenameInfo,
            rename.cast(),
            u32::try_from(buffer_len).map_err(|_| permission_error())?,
        )
    }
    .map_err(windows_error)
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(permission_error());
    }
    std::path::absolute(path).map_err(|_| permission_error())
}

fn open_path(
    path: &Path,
    access: u32,
    expected_directory: Option<bool>,
) -> io::Result<OwnedHandle> {
    open_path_shared(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        expected_directory,
    )
}

fn open_path_shared(
    path: &Path,
    access: u32,
    share: windows::Win32::Storage::FileSystem::FILE_SHARE_MODE,
    expected_directory: Option<bool>,
) -> io::Result<OwnedHandle> {
    let wide = wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            access,
            share,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(windows_error)?;
    let handle = OwnedHandle(handle);
    validate_file_handle(handle.0, expected_directory)?;
    Ok(handle)
}

fn validate_file_handle(handle: HANDLE, expected_directory: Option<bool>) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }.map_err(windows_error)?;
    let is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || expected_directory.is_some_and(|expected| expected != is_directory)
        || expected_directory == Some(false) && info.nNumberOfLinks != 1
    {
        return Err(permission_error());
    }
    Ok(())
}

fn bounded_acl(acl: *mut ACL, base: *const u8, available: usize) -> bool {
    if acl.is_null() || !range_contains(base, available, acl.cast(), std::mem::size_of::<ACL>()) {
        return false;
    }
    let acl_size = unsafe { ptr::read_unaligned(ptr::addr_of!((*acl).AclSize)) };
    let acl_size = usize::from(acl_size);
    acl_size >= std::mem::size_of::<ACL>()
        && range_contains(base, available, acl.cast(), acl_size)
        && unsafe { IsValidAcl(acl) }.as_bool()
}

fn bounded_valid_sid(sid: PSID, base: *const u8, available: usize) -> bool {
    if sid.0.is_null() || !range_contains(base, available, sid.0.cast(), 8) {
        return false;
    }
    let sid_start = sid.0.cast::<u8>();
    let sub_authority_count = usize::from(unsafe { ptr::read_unaligned(sid_start.add(1)) });
    let Some(sid_len) = sub_authority_count
        .checked_mul(std::mem::size_of::<u32>())
        .and_then(|length| length.checked_add(8))
    else {
        return false;
    };
    range_contains(base, available, sid_start, sid_len) && unsafe { IsValidSid(sid) }.as_bool()
}

fn range_contains(base: *const u8, available: usize, pointer: *const u8, length: usize) -> bool {
    let base = base as usize;
    let pointer = pointer as usize;
    pointer
        .checked_sub(base)
        .and_then(|offset| offset.checked_add(length))
        .is_some_and(|end| end <= available)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let value = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    if value.len() <= 1 || value[..value.len() - 1].contains(&0) {
        return Err(permission_error());
    }
    Ok(value)
}

fn windows_error(error: windows::core::Error) -> io::Error {
    WIN32_ERROR::from_error(&error).map_or_else(
        || io::Error::new(io::ErrorKind::PermissionDenied, error),
        |error| io::Error::from_raw_os_error(error.0 as i32),
    )
}

fn permission_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Praefectus state is not private",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_paths_fail_closed() {
        assert_eq!(
            wide_path(Path::new("")).expect_err("empty path").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn private_acl_round_trip_is_verified() {
        let directory = tempfile::tempdir().expect("temporary directory");
        restrict_directory(directory.path()).expect("restrict directory");
        validate_directory(directory.path(), true).expect("validate directory");
        let file = File::create(directory.path().join("state.json")).expect("create state");
        restrict_file(&file).expect("restrict file");
        validate_handle(
            HANDLE(file.as_raw_handle()),
            &CurrentUser::load().expect("current user"),
            true,
        )
        .expect("validate file");
    }

    #[test]
    fn hard_linked_state_file_is_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory");
        restrict_directory(directory.path()).expect("restrict directory");
        let first = directory.path().join("first.json");
        let second = directory.path().join("second.json");
        let file = File::create(&first).expect("create state");
        std::fs::hard_link(&first, second).expect("hard link");

        assert_eq!(
            restrict_file(&file).expect_err("reject hard link").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn durable_replace_uses_the_open_source() {
        let directory = tempfile::tempdir().expect("temporary directory");
        restrict_directory(directory.path()).expect("restrict directory");
        let source = directory.path().join("source.json");
        let destination = directory.path().join("destination.json");
        std::fs::write(&source, b"new").expect("write source");
        std::fs::write(&destination, b"old").expect("write destination");

        replace_file_durable(&source, &destination).expect("replace file");

        assert!(!source.exists());
        assert_eq!(
            std::fs::read(destination).expect("read destination"),
            b"new"
        );
    }

    #[test]
    fn default_ledger_is_managed_private_state() {
        let local = std::env::var_os("LOCALAPPDATA").expect("local app data");

        assert_eq!(
            crate::default_ledger_path(),
            PathBuf::from(local)
                .join("praefectus")
                .join("praefectus-operations.jsonl")
        );
    }

    #[test]
    fn bounded_sid_rejects_embedded_overflow() {
        let mut words = [0u32; 4];
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), words.len() * 4)
        };
        bytes[0] = 1;
        bytes[1] = 1;
        bytes[7] = 5;
        bytes[8..12].copy_from_slice(&18u32.to_ne_bytes());
        let sid = PSID(words.as_mut_ptr().cast());

        assert!(bounded_valid_sid(sid, words.as_ptr().cast(), 12));
        bytes[1] = 8;
        assert!(!bounded_valid_sid(sid, words.as_ptr().cast(), 12));
    }

    #[test]
    fn pointer_ranges_are_checked_without_wrapping() {
        let bytes = [0u8; 16];
        let base = bytes.as_ptr();

        assert!(range_contains(base, bytes.len(), unsafe { base.add(8) }, 8));
        assert!(!range_contains(
            base,
            bytes.len(),
            usize::MAX as *const u8,
            2
        ));
    }

    #[test]
    fn ancestor_access_rejects_replacement_rights() {
        assert!(ancestor_access_can_replace(FILE_DELETE_CHILD.0, false));
        assert!(ancestor_access_can_replace(WRITE_DAC.0, false));
        assert!(ancestor_access_can_replace(FILE_ADD_SUBDIRECTORY.0, true));
        assert!(!ancestor_access_can_replace(FILE_ADD_SUBDIRECTORY.0, false));
    }

    #[test]
    fn synthetic_ancestor_acl_rejects_untrusted_delete_child() {
        let user = CurrentUser::load().expect("current user");
        let mut sid = PSID::default();
        unsafe {
            ConvertStringSidToSidW(w!("S-1-5-21-1-2-3-1001"), &mut sid).expect("synthetic sid")
        };
        let allocation = LocalAllocation(sid.0);
        let mut storage = vec![0usize; 64];
        let acl = storage.as_mut_ptr().cast::<ACL>();
        unsafe {
            windows::Win32::Security::InitializeAcl(
                acl,
                u32::try_from(storage.len() * std::mem::size_of::<usize>()).expect("acl size"),
                windows::Win32::Security::ACL_REVISION,
            )
            .expect("initialize acl");
            windows::Win32::Security::AddAccessAllowedAce(
                acl,
                windows::Win32::Security::ACL_REVISION,
                FILE_DELETE_CHILD.0,
                sid,
            )
            .expect("add ace");
        }
        assert_eq!(
            validate_ancestor_acl(
                acl,
                storage.as_ptr().cast(),
                storage.len() * std::mem::size_of::<usize>(),
                &user,
                true,
            )
            .expect_err("reject untrusted replacement grant")
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut raw_ace = ptr::null_mut();
        unsafe {
            GetAce(acl, 0, &mut raw_ace).expect("get synthetic ace");
            (*raw_ace.cast::<ACCESS_ALLOWED_ACE>()).Mask = READ_CONTROL.0;
        }
        validate_ancestor_acl(
            acl,
            storage.as_ptr().cast(),
            storage.len() * std::mem::size_of::<usize>(),
            &user,
            true,
        )
        .expect("allow untrusted read-only ace");
        unsafe { (*raw_ace.cast::<ACE_HEADER>()).AceType = u8::MAX };
        assert_eq!(
            validate_ancestor_acl(
                acl,
                storage.as_ptr().cast(),
                storage.len() * std::mem::size_of::<usize>(),
                &user,
                true,
            )
            .expect_err("reject unknown ace")
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(allocation);
    }
}
