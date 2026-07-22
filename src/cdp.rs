use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tungstenite::client::client_with_config;
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};

use crate::semantic::{
    Actionability, MAX_SEMANTIC_ELEMENTS, MAX_SEMANTIC_OBSERVATION_AGE_MS, SemanticBackend,
    SemanticElement, SemanticError, SemanticObservation, SemanticProvenance, SemanticTargetRef,
    opaque_element_id, semantic_fingerprint, semantic_tag,
};
use crate::{
    Action, ActionCapability, BackgroundSupport, CancellationToken, Capabilities, DeliveryRoute,
    Direction, DispatchError, DispatchReceipt, EffectKnowledge, Evidence, Executor, FailureCode,
    NativeElement, Observation, PROTOCOL_VERSION, ProtocolError, ResolvedTarget, SessionIsolation,
    TargetRef, VerificationPolicy,
};

const BACKEND_NAME: &str = "praefectus-chromium-cdp";
const MAX_HTTP_BYTES: u64 = 1024 * 1024;
const MAX_CDP_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CDP_MESSAGES_PER_COMMAND: usize = 128;
const MAX_EDIT_BYTES: usize = 64 * 1024;
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(2);
const STABILITY_TOLERANCE_CSS_PX: f64 = 0.25;
const SCROLL_DELTA_CSS_PX: i64 = 100;
const PROBE_FUNCTION: &str = r#"function(){const hash=b=>{let h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225],k=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],n=(b.length+72)&~63,m=new Uint8Array(n),w=new Uint32Array(64);m.set(b);m[b.length]=128;let z=b.length*8;m[n-4]=z>>>24;m[n-3]=z>>>16;m[n-2]=z>>>8;m[n-1]=z;for(let o=0;o<n;o+=64){for(let i=0;i<16;i++)w[i]=(m[o+4*i]<<24|m[o+4*i+1]<<16|m[o+4*i+2]<<8|m[o+4*i+3])>>>0;for(let i=16;i<64;i++){let x=w[i-15],y=w[i-2],a=(x>>>7|x<<25)^(x>>>18|x<<14)^x>>>3,c=(y>>>17|y<<15)^(y>>>19|y<<13)^y>>>10;w[i]=(w[i-16]+a+w[i-7]+c)>>>0}let[a,c,d,e,f,g,j,l]=h;for(let i=0;i<64;i++){let q=(f>>>6|f<<26)^(f>>>11|f<<21)^(f>>>25|f<<7),u=(f&g)^(~f&j),v=(l+q+u+k[i]+w[i])>>>0,x=(a>>>2|a<<30)^(a>>>13|a<<19)^(a>>>22|a<<10),y=(a&c)^(a&d)^(c&d),t=(x+y)>>>0;l=j;j=g;g=f;f=(e+v)>>>0;e=d;d=c;c=a;a=(v+t)>>>0}h=[(h[0]+a)>>>0,(h[1]+c)>>>0,(h[2]+d)>>>0,(h[3]+e)>>>0,(h[4]+f)>>>0,(h[5]+g)>>>0,(h[6]+j)>>>0,(h[7]+l)>>>0]}return h.map(x=>x.toString(16).padStart(8,"0")).join("")},s=getComputedStyle(this),r=this.getBoundingClientRect(),input=this instanceof HTMLInputElement&&["text","search","email","tel","url","password"].includes(this.type),editable=(input||this instanceof HTMLTextAreaElement||this.isContentEditable)&&!this.readOnly,v=input||this instanceof HTMLTextAreaElement?this.value:(this.isContentEditable?this.textContent:null);let valueHash=null,valueLength=null,valueTooLarge=false;if(v!==null){const b=new TextEncoder().encode(v);valueLength=b.length;if(b.length<=65536)valueHash=hash(b);else valueTooLarge=true}return{connected:this.isConnected,visible:s.display!=="none"&&s.visibility!=="hidden"&&s.visibility!=="collapse"&&Number(s.opacity)>0&&r.width>0&&r.height>0,enabled:!this.matches(":disabled"),receives:s.pointerEvents!=="none",editable,active:document.activeElement===this,valueHash,valueLength,valueTooLarge}}"#;
const PROTECTED_PROBE_FUNCTION: &str = r#"function(){const s=getComputedStyle(this),r=this.getBoundingClientRect(),input=this instanceof HTMLInputElement&&["text","search","email","tel","url","password"].includes(this.type),editable=(input||this instanceof HTMLTextAreaElement||this.isContentEditable)&&!this.readOnly;return{connected:this.isConnected,visible:s.display!=="none"&&s.visibility!=="hidden"&&s.visibility!=="collapse"&&Number(s.opacity)>0&&r.width>0&&r.height>0,enabled:!this.matches(":disabled"),receives:s.pointerEvents!=="none",editable,active:document.activeElement===this,valueHash:null,valueLength:null,valueTooLarge:false}}"#;
const SCROLL_PROBE_FUNCTION: &str = r#"function(){const s=getComputedStyle(this),r=this.getBoundingClientRect(),x=["auto","scroll","overlay"].includes(s.overflowX),y=["auto","scroll","overlay"].includes(s.overflowY);return{connected:this.isConnected,visible:s.display!=="none"&&s.visibility!=="hidden"&&s.visibility!=="collapse"&&Number(s.opacity)>0&&r.width>0&&r.height>0,enabled:!this.matches(":disabled"),receives:s.pointerEvents!=="none",up:y&&this.scrollTop>0,down:y&&this.scrollTop+this.clientHeight<this.scrollHeight,left:x&&this.scrollLeft>0,right:x&&this.scrollLeft+this.clientWidth<this.scrollWidth,top:this.scrollTop,leftOffset:this.scrollLeft}}"#;
const SCROLL_EFFECT_FUNCTION: &str = r#"function(axis,delta){const s=getComputedStyle(this),r=this.getBoundingClientRect(),allowed=axis==="x"?["auto","scroll","overlay"].includes(s.overflowX):["auto","scroll","overlay"].includes(s.overflowY),connected=this.isConnected,visible=s.display!=="none"&&s.visibility!=="hidden"&&s.visibility!=="collapse"&&Number(s.opacity)>0&&r.width>0&&r.height>0,enabled=!this.matches(":disabled"),receives=s.pointerEvents!=="none",before=axis==="x"?this.scrollLeft:this.scrollTop,maximum=axis==="x"?Math.max(0,this.scrollWidth-this.clientWidth):Math.max(0,this.scrollHeight-this.clientHeight),intended=Math.min(maximum,Math.max(0,before+delta));if(!connected||!visible||!enabled||!receives||!allowed||!Number.isFinite(before)||!Number.isFinite(intended)||intended===before)return{eligible:false};if(axis==="x")this.scrollLeft=intended;else this.scrollTop=intended;const after=axis==="x"?this.scrollLeft:this.scrollTop;return{eligible:true,before,intended,after}}"#;
const INVOKE_EFFECT_FUNCTION: &str = r#"function(){const s=getComputedStyle(this),r=this.getBoundingClientRect(),eligible=this instanceof HTMLElement&&this.isConnected&&s.display!=="none"&&s.visibility!=="hidden"&&s.visibility!=="collapse"&&Number(s.opacity)>0&&r.width>0&&r.height>0&&!this.matches(":disabled");if(!eligible)return{eligible:false};HTMLElement.prototype.click.call(this);return{eligible:true}}"#;
const SET_VALUE_EFFECT_FUNCTION: &str = r#"function(value){const s=getComputedStyle(this),r=this.getBoundingClientRect(),input=this instanceof HTMLInputElement&&["text","search","email","tel","url","password"].includes(this.type),textarea=this instanceof HTMLTextAreaElement,editable=(input||textarea||this.isContentEditable)&&!this.readOnly;if(!this.isConnected||s.display==="none"||s.visibility==="hidden"||s.visibility==="collapse"||Number(s.opacity)<=0||r.width<=0||r.height<=0||this.matches(":disabled")||!editable)return{eligible:false};if(input)Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set.call(this,value);else if(textarea)Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,"value").set.call(this,value);else this.textContent=value;this.dispatchEvent(new InputEvent("input",{bubbles:true,inputType:"insertText",data:value}));this.dispatchEvent(new Event("change",{bubbles:true}));return{eligible:true}}"#;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CdpConfig {
    port: u16,
    target_id: String,
    browser_process_id: u32,
    process_generation: String,
    session_isolation: SessionIsolation,
}

impl CdpConfig {
    pub fn localhost(
        port: u16,
        target_id: impl Into<String>,
        browser_process_id: u32,
        process_generation: impl Into<String>,
    ) -> Result<Self, CdpError> {
        Self::localhost_with_isolation(
            port,
            target_id,
            browser_process_id,
            process_generation,
            SessionIsolation::SharedDesktop,
        )
    }

    pub fn host_isolated_localhost(
        port: u16,
        target_id: impl Into<String>,
        browser_process_id: u32,
        process_generation: impl Into<String>,
    ) -> Result<Self, CdpError> {
        Self::localhost_with_isolation(
            port,
            target_id,
            browser_process_id,
            process_generation,
            SessionIsolation::HostIsolated,
        )
    }

    fn localhost_with_isolation(
        port: u16,
        target_id: impl Into<String>,
        browser_process_id: u32,
        process_generation: impl Into<String>,
        session_isolation: SessionIsolation,
    ) -> Result<Self, CdpError> {
        let target_id = target_id.into();
        let process_generation = process_generation.into();
        if port == 0
            || browser_process_id == 0
            || !valid_identifier(&target_id, 128)
            || !valid_identifier(&process_generation, 256)
            || !matches!(
                live_process_generation(browser_process_id),
                Ok(ref live) if live == &process_generation
            )
        {
            return Err(CdpError::InvalidConfig);
        }
        Ok(Self {
            port,
            target_id,
            browser_process_id,
            process_generation,
            session_isolation,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port))
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    pub fn session_isolation(&self) -> SessionIsolation {
        self.session_isolation
    }

    pub fn process_generation(process_id: u32) -> Result<String, CdpError> {
        live_process_generation(process_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CdpChannelError {
    BeforeSend,
    AfterSend,
}

pub trait CdpChannel: Send {
    fn endpoint(&self) -> SocketAddr;
    fn target_id(&self) -> &str;
    fn command(
        &mut self,
        method: &str,
        parameters: Value,
        deadline_at_ms: i64,
    ) -> Result<Value, CdpChannelError>;
}

pub struct TungsteniteChannel {
    endpoint: SocketAddr,
    target_id: String,
    socket: WebSocket<TcpStream>,
    next_id: u64,
}

#[derive(Debug, Error)]
pub enum CdpError {
    #[error("invalid CDP configuration")]
    InvalidConfig,
    #[error("CDP protocol operation failed")]
    Protocol,
    #[error("CDP target changed")]
    StaleTarget,
    #[error("CDP target was not found")]
    TargetNotFound,
    #[error("CDP operation was cancelled")]
    Cancelled,
    #[error("CDP operation expired")]
    Expired,
    #[error("CDP action is unsupported")]
    Unsupported,
}

impl TungsteniteChannel {
    pub fn connect(config: &CdpConfig) -> Result<Self, CdpError> {
        verify_process(config)?;
        verify_endpoint_owner(config)?;
        let websocket_url = discover_websocket_url(config)?;
        verify_endpoint_owner(config)?;
        let stream = TcpStream::connect_timeout(&config.endpoint(), MAX_IO_TIMEOUT)
            .map_err(|_| CdpError::Protocol)?;
        verify_endpoint_owner(config)?;
        stream
            .set_read_timeout(Some(MAX_IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(MAX_IO_TIMEOUT)))
            .map_err(|_| CdpError::Protocol)?;
        let websocket_config = WebSocketConfig::default()
            .read_buffer_size(8 * 1024)
            .write_buffer_size(0)
            .max_write_buffer_size(MAX_CDP_MESSAGE_BYTES + 8 * 1024)
            .max_message_size(Some(MAX_CDP_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_CDP_MESSAGE_BYTES));
        let (socket, _) = client_with_config(&websocket_url, stream, Some(websocket_config))
            .map_err(|_| CdpError::Protocol)?;
        verify_endpoint_owner(config)?;
        Ok(Self {
            endpoint: config.endpoint(),
            target_id: config.target_id.clone(),
            socket,
            next_id: 0,
        })
    }
}

impl CdpChannel for TungsteniteChannel {
    fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    fn target_id(&self) -> &str {
        &self.target_id
    }

    fn command(
        &mut self,
        method: &str,
        parameters: Value,
        deadline_at_ms: i64,
    ) -> Result<Value, CdpChannelError> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(CdpChannelError::BeforeSend)?;
        set_stream_deadline(self.socket.get_mut(), deadline_at_ms)
            .map_err(|_| CdpChannelError::BeforeSend)?;
        let request = serde_json::to_string(&json!({
            "id": self.next_id,
            "method": method,
            "params": parameters,
        }))
        .map_err(|_| CdpChannelError::BeforeSend)?;
        if request.len() > MAX_CDP_MESSAGE_BYTES {
            return Err(CdpChannelError::BeforeSend);
        }
        self.socket
            .send(Message::text(request))
            .map_err(|_| CdpChannelError::AfterSend)?;
        let mut received_bytes = 0usize;
        for _ in 0..MAX_CDP_MESSAGES_PER_COMMAND {
            set_stream_deadline(self.socket.get_mut(), deadline_at_ms)
                .map_err(|_| CdpChannelError::AfterSend)?;
            let message = self.socket.read().map_err(|_| CdpChannelError::AfterSend)?;
            let Message::Text(text) = message else {
                if matches!(message, Message::Ping(_) | Message::Pong(_)) {
                    continue;
                }
                return Err(CdpChannelError::AfterSend);
            };
            received_bytes = received_bytes
                .checked_add(text.len())
                .filter(|total| *total <= MAX_CDP_MESSAGE_BYTES)
                .ok_or(CdpChannelError::AfterSend)?;
            let response: Value =
                serde_json::from_str(text.as_str()).map_err(|_| CdpChannelError::AfterSend)?;
            if let Some(result) = cdp_command_result(&response, self.next_id)? {
                return Ok(result);
            }
        }
        Err(CdpChannelError::AfterSend)
    }
}

fn cdp_command_result(response: &Value, command_id: u64) -> Result<Option<Value>, CdpChannelError> {
    match response.get("id").and_then(Value::as_u64) {
        Some(id) if id == command_id && response.get("error").is_none() => response
            .get("result")
            .cloned()
            .map(Some)
            .ok_or(CdpChannelError::AfterSend),
        Some(_) => Err(CdpChannelError::AfterSend),
        None if response
            .get("method")
            .and_then(Value::as_str)
            .is_some_and(|method| !method.is_empty()) =>
        {
            Ok(None)
        }
        None => Err(CdpChannelError::AfterSend),
    }
}

impl CdpExecutor<TungsteniteChannel> {
    pub fn connect(config: CdpConfig) -> Result<Self, CdpError> {
        let channel = TungsteniteChannel::connect(&config)?;
        Self::new(config, channel)
    }
}

struct CdpNode {
    backend_node_id: u64,
    protected: bool,
    element: SemanticElement,
}

struct StoredObservation {
    observation: SemanticObservation,
    execution_context_id: u64,
    nodes: BTreeMap<String, CdpNode>,
}

pub struct CdpExecutor<C> {
    config: CdpConfig,
    channel: Mutex<C>,
    generation: AtomicU64,
    latest: RwLock<Option<StoredObservation>>,
}

impl<C: CdpChannel> CdpExecutor<C> {
    pub fn new(config: CdpConfig, channel: C) -> Result<Self, CdpError> {
        if channel.endpoint() != config.endpoint() || channel.target_id() != config.target_id() {
            return Err(CdpError::InvalidConfig);
        }
        verify_process(&config)?;
        Ok(Self {
            config,
            channel: Mutex::new(channel),
            generation: AtomicU64::new(0),
            latest: RwLock::new(None),
        })
    }

    pub fn semantic_observation(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<SemanticObservation, CdpError> {
        boundary(cancellation, deadline_at_ms)?;
        verify_process(&self.config)?;
        let target = self.command(
            cancellation,
            deadline_at_ms,
            "Target.getTargetInfo",
            json!({"targetId": self.config.target_id}),
        )?;
        let target_info = target.get("targetInfo").ok_or(CdpError::Protocol)?;
        if target_info.get("targetId").and_then(Value::as_str)
            != Some(self.config.target_id.as_str())
            || !matches!(
                target_info.get("type").and_then(Value::as_str),
                Some("page" | "webview")
            )
        {
            return Err(CdpError::StaleTarget);
        }
        let frame_tree =
            self.command(cancellation, deadline_at_ms, "Page.getFrameTree", json!({}))?;
        let frame = frame_tree
            .pointer("/frameTree/frame")
            .ok_or(CdpError::Protocol)?;
        let frame_id = required_string(frame, "id")?;
        let loader_id = required_string(frame, "loaderId")?;
        let document_id = semantic_fingerprint(&(
            BACKEND_NAME,
            self.config.target_id.as_str(),
            frame_id,
            loader_id,
        ))
        .map_err(|_| CdpError::Protocol)?;
        let execution_context = self.command(
            cancellation,
            deadline_at_ms,
            "Page.createIsolatedWorld",
            json!({
                "frameId": frame_id,
                "worldName": "praefectus",
                "grantUniversalAccess": false,
            }),
        )?;
        let execution_context_id = execution_context
            .get("executionContextId")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or(CdpError::Protocol)?;
        let layout = self.command(
            cancellation,
            deadline_at_ms,
            "Page.getLayoutMetrics",
            json!({}),
        )?;
        let viewport = layout
            .get("cssVisualViewport")
            .or_else(|| layout.get("visualViewport"))
            .ok_or(CdpError::Protocol)?;
        let display_geometry_hash =
            semantic_fingerprint(viewport).map_err(|_| CdpError::Protocol)?;
        let dom_snapshot = self.command(
            cancellation,
            deadline_at_ms,
            "DOMSnapshot.captureSnapshot",
            json!({
                "computedStyles": [],
                "includeDOMRects": false,
                "includePaintOrder": false,
                "includeBlendedBackgroundColors": false,
                "includeTextColorOpacities": false,
            }),
        )?;
        let root_backend_node_ids = root_backend_node_ids(&dom_snapshot, frame_id)?;
        let tree = self.command(
            cancellation,
            deadline_at_ms,
            "Accessibility.getFullAXTree",
            json!({"frameId": frame_id}),
        )?;
        let final_frame_tree =
            self.command(cancellation, deadline_at_ms, "Page.getFrameTree", json!({}))?;
        let final_frame = final_frame_tree
            .pointer("/frameTree/frame")
            .ok_or(CdpError::Protocol)?;
        if required_string(final_frame, "id")? != frame_id
            || required_string(final_frame, "loaderId")? != loader_id
        {
            return Err(CdpError::StaleTarget);
        }
        boundary(cancellation, deadline_at_ms)?;

        let observed_at_ms = now_ms();
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let observation_id = semantic_fingerprint(&(
            BACKEND_NAME,
            self.config.target_id.as_str(),
            document_id.as_str(),
            generation,
            observed_at_ms,
        ))
        .map_err(|_| CdpError::Protocol)?;
        let (elements, nodes) =
            parse_ax_tree(&tree, &observation_id, &document_id, &root_backend_node_ids)?;
        let observation = SemanticObservation {
            protocol_version: PROTOCOL_VERSION,
            observation_id,
            generation,
            provenance: SemanticProvenance {
                backend: SemanticBackend::Dom,
                backend_name: BACKEND_NAME.to_string(),
                process_id: self.config.browser_process_id,
                process_generation: self.config.process_generation.clone(),
                window_id: self.config.target_id.clone(),
                document_id: Some(document_id),
                display_geometry_hash,
            },
            observed_at_ms,
            expires_at_ms: deadline_at_ms
                .min(observed_at_ms.saturating_add(MAX_SEMANTIC_OBSERVATION_AGE_MS)),
            truncated: false,
            elements,
        };
        observation
            .validate(observed_at_ms)
            .map_err(|_| CdpError::Protocol)?;
        *self.latest.write().map_err(|_| CdpError::Protocol)? = Some(StoredObservation {
            observation: observation.clone(),
            execution_context_id,
            nodes,
        });
        Ok(observation)
    }

    pub fn engine_target(
        &self,
        target: &SemanticTargetRef,
        now_ms: i64,
    ) -> Result<TargetRef, CdpError> {
        let _: NodeIdentity = self.stored_node(target, now_ms)?;
        Ok(TargetRef::Element {
            target: target.clone(),
        })
    }

    fn command(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
        method: &str,
        parameters: Value,
    ) -> Result<Value, CdpError> {
        boundary(cancellation, deadline_at_ms)?;
        let result = self
            .channel
            .lock()
            .map_err(|_| CdpError::Protocol)?
            .command(method, parameters, deadline_at_ms)
            .map_err(|_| CdpError::Protocol);
        boundary(cancellation, deadline_at_ms)?;
        result
    }

    fn stored_node<T>(&self, target: &SemanticTargetRef, now_ms: i64) -> Result<T, CdpError>
    where
        T: FromStoredNode,
    {
        let latest = self.latest.read().map_err(|_| CdpError::Protocol)?;
        let stored = latest.as_ref().ok_or(CdpError::TargetNotFound)?;
        stored
            .observation
            .resolve(target, now_ms)
            .map_err(map_semantic_error)?;
        let node = stored
            .nodes
            .get(&target.element_id)
            .ok_or(CdpError::TargetNotFound)?;
        Ok(T::from_stored(node, stored))
    }

    fn current_document_id(&self, deadline_at_ms: i64) -> Result<String, ProtocolError> {
        let frame_tree = self
            .channel
            .lock()
            .map_err(|_| backend_error())?
            .command("Page.getFrameTree", json!({}), deadline_at_ms)
            .map_err(|_| backend_error())?;
        let frame = frame_tree
            .pointer("/frameTree/frame")
            .ok_or_else(backend_error)?;
        let frame_id = required_string(frame, "id").map_err(|_| backend_error())?;
        let loader_id = required_string(frame, "loaderId").map_err(|_| backend_error())?;
        semantic_fingerprint(&(
            BACKEND_NAME,
            self.config.target_id.as_str(),
            frame_id,
            loader_id,
        ))
        .map_err(|_| backend_error())
    }

    fn resolve_object(
        &self,
        backend_node_id: u64,
        execution_context_id: u64,
        deadline_at_ms: i64,
    ) -> Result<String, ProtocolError> {
        let response = self
            .channel
            .lock()
            .map_err(|_| backend_error())?
            .command(
                "DOM.resolveNode",
                json!({
                    "backendNodeId": backend_node_id,
                    "executionContextId": execution_context_id,
                }),
                deadline_at_ms,
            )
            .map_err(|_| backend_error())?;
        response
            .pointer("/object/objectId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| ProtocolError::StaleTarget("browser target changed".to_string()))
    }

    fn live_probe(
        &self,
        target: &SemanticTargetRef,
        deadline_at_ms: i64,
    ) -> Result<LiveProbe, ProtocolError> {
        verify_process(&self.config).map_err(|_| backend_error())?;
        let node: NodeIdentity = self
            .stored_node(target, now_ms())
            .map_err(map_cdp_protocol_error)?;
        let document_id = self.current_document_id(deadline_at_ms)?;
        if document_id != node.document_id {
            return Err(ProtocolError::StaleTarget(
                "browser document changed".to_string(),
            ));
        }
        let object_id = self.resolve_object(
            node.backend_node_id,
            node.execution_context_id,
            deadline_at_ms,
        )?;
        let response = self
            .channel
            .lock()
            .map_err(|_| backend_error())?
            .command(
                "Runtime.callFunctionOn",
                json!({
                    "objectId": object_id,
                    "functionDeclaration": if node.protected {
                        PROTECTED_PROBE_FUNCTION
                    } else {
                        PROBE_FUNCTION
                    },
                    "awaitPromise": true,
                    "returnByValue": true,
                }),
                deadline_at_ms,
            )
            .map_err(|_| backend_error())?;
        if response.get("exceptionDetails").is_some() {
            return Err(ProtocolError::StaleTarget(
                "browser target changed".to_string(),
            ));
        }
        let value = response
            .pointer("/result/value")
            .cloned()
            .ok_or_else(backend_error)?;
        if value.get("connected").and_then(Value::as_bool) != Some(true) {
            return Err(ProtocolError::StaleTarget(
                "browser target changed".to_string(),
            ));
        }
        let layout = self
            .channel
            .lock()
            .map_err(|_| backend_error())?
            .command("Page.getLayoutMetrics", json!({}), deadline_at_ms)
            .map_err(|_| backend_error())?;
        let viewport = layout
            .get("cssVisualViewport")
            .or_else(|| layout.get("visualViewport"))
            .ok_or_else(backend_error)?;
        let display_geometry_hash = semantic_fingerprint(viewport).map_err(|_| backend_error())?;
        let tree = self
            .channel
            .lock()
            .map_err(|_| backend_error())?
            .command(
                "Accessibility.getPartialAXTree",
                json!({
                    "backendNodeId": node.backend_node_id,
                    "fetchRelatives": false,
                }),
                deadline_at_ms,
            )
            .map_err(|_| backend_error())?;
        let semantics = live_ax_semantics(&tree, node.backend_node_id)
            .map_err(|_| ProtocolError::StaleTarget("browser target changed".to_string()))?;
        let fingerprint_hash = semantic_fingerprint(&(
            document_id.as_str(),
            node.backend_node_id,
            semantics.role.as_str(),
            semantics.name.as_deref(),
        ))
        .map_err(|_| backend_error())?;
        verify_process(&self.config).map_err(|_| backend_error())?;
        if display_geometry_hash != node.display_geometry_hash
            || fingerprint_hash != node.fingerprint_hash
        {
            return Err(ProtocolError::StaleTarget(
                "browser target changed".to_string(),
            ));
        }
        Ok(LiveProbe {
            state: redacted_probe(value, node.protected),
            fingerprint_hash,
            display_geometry_hash,
        })
    }

    fn verify_process_for_effect(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let result = verify_process(&self.config);
        check_effect_boundary(cancellation, deadline_at_ms)?;
        result.map_err(|_| no_effect("browser process changed"))
    }

    fn current_document_id_for_effect(
        &self,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<String, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let result = self.current_document_id(deadline_at_ms);
        check_effect_boundary(cancellation, deadline_at_ms)?;
        result.map_err(|_| no_effect("browser document is unavailable"))
    }

    fn resolve_object_for_effect(
        &self,
        backend_node_id: u64,
        execution_context_id: u64,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<String, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let result = self.resolve_object(backend_node_id, execution_context_id, deadline_at_ms);
        check_effect_boundary(cancellation, deadline_at_ms)?;
        result.map_err(|_| no_effect("browser target changed"))
    }

    fn effect_command(
        &self,
        method: &str,
        parameters: Value,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
        effect_started: bool,
    ) -> Result<Value, DispatchError> {
        if effect_started {
            check_after_effect_boundary(cancellation, deadline_at_ms)?;
        } else {
            check_effect_boundary(cancellation, deadline_at_ms)?;
        }
        let result = self
            .channel
            .lock()
            .map_err(|_| {
                if effect_started {
                    unknown("browser effect outcome is unknown")
                } else {
                    no_effect("browser channel is unavailable")
                }
            })?
            .command(method, parameters, deadline_at_ms);
        match result {
            Ok(value) => Ok(value),
            Err(_) if effect_started => Err(unknown("browser effect outcome is unknown")),
            Err(CdpChannelError::AfterSend) => Err(unknown("browser effect outcome is unknown")),
            Err(CdpChannelError::BeforeSend) => {
                check_effect_boundary(cancellation, deadline_at_ms)?;
                Err(no_effect("browser effect was not dispatched"))
            }
        }
    }

    fn query_for_effect(
        &self,
        method: &str,
        parameters: Value,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Value, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let result = self
            .channel
            .lock()
            .map_err(|_| no_effect("browser channel is unavailable"))?
            .command(method, parameters, deadline_at_ms);
        check_effect_boundary(cancellation, deadline_at_ms)?;
        result.map_err(|_| no_effect("browser target is unavailable"))
    }

    fn probe_object_for_effect(
        &self,
        object_id: &str,
        options: EffectProbe,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Value, DispatchError> {
        let function = if options.protected && !options.reveal_value {
            PROTECTED_PROBE_FUNCTION
        } else {
            PROBE_FUNCTION
        };
        let response = if options.effect_started {
            self.effect_command(
                "Runtime.callFunctionOn",
                json!({
                    "objectId": object_id,
                    "functionDeclaration": function,
                    "awaitPromise": true,
                    "returnByValue": true,
                }),
                cancellation,
                deadline_at_ms,
                true,
            )?
        } else {
            self.query_for_effect(
                "Runtime.callFunctionOn",
                json!({
                    "objectId": object_id,
                    "functionDeclaration": function,
                    "awaitPromise": true,
                    "returnByValue": true,
                }),
                cancellation,
                deadline_at_ms,
            )?
        };
        if response.get("exceptionDetails").is_some() {
            return Err(if options.effect_started {
                unknown("browser effect outcome is unknown")
            } else {
                no_effect("browser target changed")
            });
        }
        response.pointer("/result/value").cloned().ok_or_else(|| {
            if options.effect_started {
                unknown("browser effect outcome is unknown")
            } else {
                no_effect("browser target changed")
            }
        })
    }

    fn verify_live_target_for_effect(
        &self,
        target: &NodeIdentity,
        requirements: LiveTargetRequirements,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<(), DispatchError> {
        let layout = self.query_for_effect(
            "Page.getLayoutMetrics",
            json!({}),
            cancellation,
            deadline_at_ms,
        )?;
        let viewport = layout
            .get("cssVisualViewport")
            .or_else(|| layout.get("visualViewport"))
            .ok_or_else(|| no_effect("browser viewport is unavailable"))?;
        let display_geometry_hash =
            semantic_fingerprint(viewport).map_err(|_| no_effect("browser viewport changed"))?;
        if display_geometry_hash != target.display_geometry_hash {
            return Err(no_effect("browser viewport changed"));
        }
        let document_id = self.current_document_id_for_effect(cancellation, deadline_at_ms)?;
        let tree = self.query_for_effect(
            "Accessibility.getPartialAXTree",
            json!({
                "backendNodeId": target.backend_node_id,
                "fetchRelatives": false,
            }),
            cancellation,
            deadline_at_ms,
        )?;
        let semantics = live_ax_semantics(&tree, target.backend_node_id)?;
        let fingerprint_hash = semantic_fingerprint(&(
            document_id.as_str(),
            target.backend_node_id,
            semantics.role.as_str(),
            semantics.name.as_deref(),
        ))
        .map_err(|_| no_effect("browser target changed"))?;
        if fingerprint_hash != target.fingerprint_hash
            || !semantics.visible
            || !semantics.enabled
            || (requirements.invokable && !semantics.invokable)
            || (requirements.editable && !semantics.editable)
        {
            return Err(no_effect("browser target changed"));
        }
        Ok(())
    }

    fn dispatch_invoke(
        &self,
        target: &NodeIdentity,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        let object_id = self.resolve_object_for_effect(
            target.backend_node_id,
            target.execution_context_id,
            cancellation,
            deadline_at_ms,
        )?;
        let probe = self.probe_object_for_effect(
            &object_id,
            EffectProbe {
                protected: target.protected,
                reveal_value: false,
                effect_started: false,
            },
            cancellation,
            deadline_at_ms,
        )?;
        if probe.get("connected").and_then(Value::as_bool) != Some(true)
            || probe.get("visible").and_then(Value::as_bool) != Some(true)
            || probe.get("enabled").and_then(Value::as_bool) != Some(true)
        {
            return Err(no_effect("browser target is not actionable"));
        }
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        self.verify_live_target_for_effect(
            target,
            LiveTargetRequirements {
                invokable: true,
                editable: false,
            },
            cancellation,
            deadline_at_ms,
        )?;
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        let response = self.effect_command(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": INVOKE_EFFECT_FUNCTION,
                "returnByValue": true,
            }),
            cancellation,
            deadline_at_ms,
            false,
        )?;
        check_after_effect_boundary(cancellation, deadline_at_ms)?;
        if response.get("exceptionDetails").is_some() {
            return Err(unknown("browser invoke outcome is unknown"));
        }
        match response
            .pointer("/result/value/eligible")
            .and_then(Value::as_bool)
        {
            Some(true) => Ok(success_receipt()),
            Some(false) => Err(no_effect("browser target is not invokable")),
            None => Err(unknown("browser invoke outcome is unknown")),
        }
    }

    fn dispatch_scroll(
        &self,
        target: &NodeIdentity,
        direction: Direction,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        let object_id = self.resolve_object_for_effect(
            target.backend_node_id,
            target.execution_context_id,
            cancellation,
            deadline_at_ms,
        )?;
        let probe = self.query_for_effect(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": SCROLL_PROBE_FUNCTION,
                "returnByValue": true,
            }),
            cancellation,
            deadline_at_ms,
        )?;
        let probe = probe
            .pointer("/result/value")
            .ok_or_else(|| no_effect("browser target changed"))?;
        if probe.get("connected").and_then(Value::as_bool) != Some(true)
            || probe.get("visible").and_then(Value::as_bool) != Some(true)
            || probe.get("enabled").and_then(Value::as_bool) != Some(true)
            || probe.get("receives").and_then(Value::as_bool) != Some(true)
            || probe
                .get(scroll_direction_name(direction))
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(no_effect("browser target is not scrollable"));
        }
        let first_box = self.query_for_effect(
            "DOM.getBoxModel",
            json!({"backendNodeId": target.backend_node_id}),
            cancellation,
            deadline_at_ms,
        )?;
        self.query_for_effect(
            "Runtime.evaluate",
            json!({
                "expression": "new Promise(r=>requestAnimationFrame(()=>r(true)))",
                "awaitPromise": true,
                "returnByValue": true,
            }),
            cancellation,
            deadline_at_ms,
        )?;
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let second_box = self.query_for_effect(
            "DOM.getBoxModel",
            json!({"backendNodeId": target.backend_node_id}),
            cancellation,
            deadline_at_ms,
        )?;
        let first_quad = border_quad(&first_box)?;
        let second_quad = border_quad(&second_box)?;
        if first_quad
            .iter()
            .zip(second_quad.iter())
            .any(|(first, second)| (first - second).abs() > STABILITY_TOLERANCE_CSS_PX)
        {
            return Err(no_effect("browser target is not stable"));
        }
        let layout = self.query_for_effect(
            "Page.getLayoutMetrics",
            json!({}),
            cancellation,
            deadline_at_ms,
        )?;
        let (x, y) = viewport_point(&second_quad, &layout)?;
        let hit = self.query_for_effect(
            "DOM.getNodeForLocation",
            json!({
                "x": x,
                "y": y,
                "includeUserAgentShadowDOM": true,
                "ignorePointerEventsNone": false,
            }),
            cancellation,
            deadline_at_ms,
        )?;
        let hit_backend_node_id = hit
            .get("backendNodeId")
            .and_then(Value::as_u64)
            .ok_or_else(|| no_effect("browser target does not receive events"))?;
        if hit_backend_node_id != target.backend_node_id {
            return Err(no_effect("browser target does not receive events"));
        }
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        self.verify_live_target_for_effect(
            target,
            LiveTargetRequirements {
                invokable: false,
                editable: false,
            },
            cancellation,
            deadline_at_ms,
        )?;
        let probe = self.query_for_effect(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": SCROLL_PROBE_FUNCTION,
                "returnByValue": true,
            }),
            cancellation,
            deadline_at_ms,
        )?;
        if probe
            .pointer("/result/value")
            .and_then(|value| value.get(scroll_direction_name(direction)))
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(no_effect("browser target is not scrollable"));
        }
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        let (axis, delta) = scroll_axis_delta(direction);
        let response = self.effect_command(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": SCROLL_EFFECT_FUNCTION,
                "arguments": [{"value": axis}, {"value": delta}],
                "returnByValue": true,
            }),
            cancellation,
            deadline_at_ms,
            false,
        )?;
        check_after_effect_boundary(cancellation, deadline_at_ms)?;
        if response.get("exceptionDetails").is_some() {
            return Err(unknown("browser scroll outcome is unknown"));
        }
        let result = response
            .pointer("/result/value")
            .ok_or_else(|| unknown("browser scroll outcome is unknown"))?;
        match result.get("eligible").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => return Err(no_effect("browser target is not scrollable")),
            None => return Err(unknown("browser scroll outcome is unknown")),
        }
        let before = result
            .get("before")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or_else(|| unknown("browser scroll outcome is unknown"))?;
        let intended = result
            .get("intended")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or_else(|| unknown("browser scroll outcome is unknown"))?;
        let after = result
            .get("after")
            .and_then(Value::as_f64)
            .filter(|value| value.is_finite())
            .ok_or_else(|| unknown("browser scroll outcome is unknown"))?;
        let moved_in_direction = match direction {
            Direction::Up | Direction::Left => after < before,
            Direction::Down | Direction::Right => after > before,
        };
        if after != intended || !moved_in_direction {
            return Err(unknown("browser scroll verification failed"));
        }
        Ok(success_receipt())
    }

    fn dispatch_set_value(
        &self,
        target: &NodeIdentity,
        value: &str,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        if value.len() > MAX_EDIT_BYTES {
            return Err(no_effect("browser value is too large"));
        }
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        let object_id = self.resolve_object_for_effect(
            target.backend_node_id,
            target.execution_context_id,
            cancellation,
            deadline_at_ms,
        )?;
        let probe = self.probe_object_for_effect(
            &object_id,
            EffectProbe {
                protected: target.protected,
                reveal_value: false,
                effect_started: false,
            },
            cancellation,
            deadline_at_ms,
        )?;
        if probe.get("connected").and_then(Value::as_bool) != Some(true)
            || probe.get("visible").and_then(Value::as_bool) != Some(true)
            || probe.get("enabled").and_then(Value::as_bool) != Some(true)
            || probe.get("editable").and_then(Value::as_bool) != Some(true)
        {
            return Err(no_effect("browser target is not actionable"));
        }
        self.verify_live_target_for_effect(
            target,
            LiveTargetRequirements {
                invokable: false,
                editable: true,
            },
            cancellation,
            deadline_at_ms,
        )?;
        check_effect_boundary(cancellation, deadline_at_ms)?;
        self.verify_process_for_effect(cancellation, deadline_at_ms)?;
        let response = self.effect_command(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": SET_VALUE_EFFECT_FUNCTION,
                "arguments": [{"value": value}],
                "returnByValue": true,
            }),
            cancellation,
            deadline_at_ms,
            false,
        )?;
        check_after_effect_boundary(cancellation, deadline_at_ms)?;
        if response.get("exceptionDetails").is_some() {
            return Err(unknown("browser value outcome is unknown"));
        }
        match response
            .pointer("/result/value/eligible")
            .and_then(Value::as_bool)
        {
            Some(true) => {}
            Some(false) => return Err(no_effect("browser target is not editable")),
            None => return Err(unknown("browser value outcome is unknown")),
        }
        verify_process(&self.config).map_err(|_| unknown("browser effect outcome is unknown"))?;
        let after = self.probe_object_for_effect(
            &object_id,
            EffectProbe {
                protected: target.protected,
                reveal_value: true,
                effect_started: true,
            },
            cancellation,
            deadline_at_ms,
        )?;
        let expected_hash = hex::encode(Sha256::digest(value.as_bytes()));
        if after.get("valueHash").and_then(Value::as_str) != Some(expected_hash.as_str())
            || after.get("valueLength").and_then(Value::as_u64) != u64::try_from(value.len()).ok()
            || after.get("valueTooLarge").and_then(Value::as_bool) != Some(false)
        {
            return Err(unknown("browser value verification failed"));
        }
        Ok(success_receipt())
    }
}

trait FromStoredNode: Sized {
    fn from_stored(node: &CdpNode, stored: &StoredObservation) -> Self;
}

struct NodeIdentity {
    backend_node_id: u64,
    execution_context_id: u64,
    document_id: String,
    protected: bool,
    fingerprint_hash: String,
    display_geometry_hash: String,
}

struct LiveProbe {
    state: Value,
    fingerprint_hash: String,
    display_geometry_hash: String,
}

struct EffectProbe {
    protected: bool,
    reveal_value: bool,
    effect_started: bool,
}

struct LiveTargetRequirements {
    invokable: bool,
    editable: bool,
}

impl FromStoredNode for NodeIdentity {
    fn from_stored(node: &CdpNode, stored: &StoredObservation) -> Self {
        Self {
            backend_node_id: node.backend_node_id,
            execution_context_id: stored.execution_context_id,
            protected: node.protected,
            fingerprint_hash: node.element.fingerprint_hash.clone(),
            display_geometry_hash: stored.observation.provenance.display_geometry_hash.clone(),
            document_id: stored
                .observation
                .provenance
                .document_id
                .clone()
                .unwrap_or_default(),
        }
    }
}

impl FromStoredNode for NativeElement {
    fn from_stored(node: &CdpNode, stored: &StoredObservation) -> Self {
        let observation = &stored.observation;
        Self {
            backend: BACKEND_NAME.to_string(),
            id: node.element.element_id.clone(),
            app: "chromium".to_string(),
            process_id: i32::try_from(observation.provenance.process_id).ok(),
            window: Some(observation.provenance.window_id.clone()),
            role: node.element.role.clone(),
            label: node.element.name.clone(),
            title: None,
            bounds: None,
            state: serde_json::to_value(node.element.actionability).unwrap_or(Value::Null),
            enabled: Some(node.element.actionability.enabled),
        }
    }
}

impl<C: CdpChannel + Send> Executor for CdpExecutor<C> {
    fn session_isolation(&self) -> SessionIsolation {
        self.config.session_isolation
    }

    fn capabilities(&self) -> Result<Capabilities, ProtocolError> {
        let backend_available = verify_endpoint_owner(&self.config).is_ok()
            && self.channel.lock().is_ok_and(|channel| {
                channel.endpoint() == self.config.endpoint()
                    && channel.target_id() == self.config.target_id()
            });
        let latest = self.latest.read().map_err(|_| backend_error())?;
        let current = latest
            .as_ref()
            .filter(|stored| stored.observation.validate(now_ms()).is_ok());
        let available = backend_available && current.is_some();
        let display_geometry_hash = match (backend_available, current) {
            (true, Some(stored)) => stored.observation.provenance.display_geometry_hash.clone(),
            _ => "0".repeat(64),
        };
        Ok(Capabilities {
            platform: "browser".to_string(),
            backend: BACKEND_NAME.to_string(),
            supported_actions: if available {
                vec![
                    "invoke".to_string(),
                    "scroll".to_string(),
                    "set_value".to_string(),
                ]
            } else {
                Vec::new()
            },
            action_capabilities: if available {
                vec![
                    ActionCapability {
                        action: "invoke".to_string(),
                        delivery_route: DeliveryRoute::TargetAddressed,
                        background_support: BackgroundSupport::HostIsolatedOnly,
                    },
                    ActionCapability {
                        action: "scroll".to_string(),
                        delivery_route: DeliveryRoute::TargetAddressed,
                        background_support: BackgroundSupport::HostIsolatedOnly,
                    },
                    ActionCapability {
                        action: "set_value".to_string(),
                        delivery_route: DeliveryRoute::TargetAddressed,
                        background_support: BackgroundSupport::HostIsolatedOnly,
                    },
                ]
            } else {
                Vec::new()
            },
            permissions: BTreeMap::from([
                ("cdp".to_string(), available),
                ("coordinates".to_string(), false),
                ("root_frame_only".to_string(), true),
                ("screenshots".to_string(), false),
            ]),
            display_geometry_hash,
        })
    }

    fn observe(&self, target: &TargetRef) -> Result<Observation, ProtocolError> {
        self.observe_with_boundary(target, &CancellationToken::default(), i64::MAX)
    }

    fn observe_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<Observation, ProtocolError> {
        boundary(cancellation, deadline_at_ms).map_err(map_cdp_protocol_error)?;
        let TargetRef::Element { target } = target else {
            return Err(ProtocolError::TargetNotFound(
                "browser semantic target required".to_string(),
            ));
        };
        let probe = self.live_probe(target, deadline_at_ms);
        boundary(cancellation, deadline_at_ms).map_err(map_cdp_protocol_error)?;
        let probe = probe?;
        let latest = self.latest.read().map_err(|_| backend_error())?;
        latest.as_ref().ok_or_else(backend_error)?;
        let observation_hash =
            semantic_fingerprint(&(target, &probe.state)).map_err(|_| backend_error())?;
        boundary(cancellation, deadline_at_ms).map_err(map_cdp_protocol_error)?;
        Ok(Observation {
            evidence: Evidence {
                observation_hash,
                target_fingerprint_hash: Some(probe.fingerprint_hash),
                display_geometry_hash: probe.display_geometry_hash,
                observed_at_ms: now_ms(),
            },
            element: None,
            state: probe.state,
        })
    }

    fn resolve(&self, target: &TargetRef) -> Result<ResolvedTarget, ProtocolError> {
        self.resolve_with_boundary(target, &CancellationToken::default(), i64::MAX)
    }

    fn resolve_with_boundary(
        &self,
        target: &TargetRef,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<ResolvedTarget, ProtocolError> {
        boundary(cancellation, deadline_at_ms).map_err(map_cdp_protocol_error)?;
        let TargetRef::Element { target } = target else {
            return Err(ProtocolError::TargetNotFound(
                "browser semantic target required".to_string(),
            ));
        };
        self.stored_node::<NativeElement>(target, now_ms())
            .map(|element| ResolvedTarget::Element(Box::new(element)))
            .map_err(map_cdp_protocol_error)
    }

    fn dispatch(
        &self,
        action: &Action,
        target: &ResolvedTarget,
        verification: &VerificationPolicy,
        cancellation: &CancellationToken,
        deadline_at_ms: i64,
    ) -> Result<DispatchReceipt, DispatchError> {
        check_effect_boundary(cancellation, deadline_at_ms)?;
        let ResolvedTarget::Element(element) = target else {
            return Err(no_effect("browser semantic target required"));
        };
        if element.backend != BACKEND_NAME {
            return Err(no_effect("browser semantic target changed"));
        }
        if matches!(action, Action::Scroll { amount, .. } if *amount != 1)
            || (matches!(action, Action::Scroll { .. })
                && !matches!(verification, VerificationPolicy::None))
        {
            return Err(unsupported());
        }
        if matches!(action, Action::Click { .. }) {
            return Err(unsupported());
        }
        let latest = self
            .latest
            .read()
            .map_err(|_| no_effect("browser target is unavailable"))?;
        let stored = latest
            .as_ref()
            .ok_or_else(|| no_effect("browser target is unavailable"))?;
        let node = stored
            .nodes
            .get(&element.id)
            .ok_or_else(|| no_effect("browser target changed"))?;
        let identity = NodeIdentity::from_stored(node, stored);
        let invokable = node.element.actionability.invokable;
        let editable = node.element.actionability.editable;
        let visible = node.element.actionability.visible;
        let enabled = node.element.actionability.enabled;
        drop(latest);
        if self.current_document_id_for_effect(cancellation, deadline_at_ms)?
            != identity.document_id
        {
            return Err(no_effect("browser document changed"));
        }
        check_effect_boundary(cancellation, deadline_at_ms)?;
        if !visible || !enabled {
            return Err(no_effect("browser target is not actionable"));
        }
        match action {
            Action::Invoke if invokable => {
                self.dispatch_invoke(&identity, cancellation, deadline_at_ms)
            }
            Action::SetValue { value } if editable => {
                self.dispatch_set_value(&identity, value, cancellation, deadline_at_ms)
            }
            Action::Scroll {
                direction,
                amount: 1,
            } => self.dispatch_scroll(&identity, *direction, cancellation, deadline_at_ms),
            _ => Err(unsupported()),
        }
    }
}

fn discover_websocket_url(config: &CdpConfig) -> Result<String, CdpError> {
    let mut stream = TcpStream::connect_timeout(&config.endpoint(), MAX_IO_TIMEOUT)
        .map_err(|_| CdpError::Protocol)?;
    stream
        .set_read_timeout(Some(MAX_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(MAX_IO_TIMEOUT)))
        .map_err(|_| CdpError::Protocol)?;
    write!(
        stream,
        "GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nAccept: application/json\r\n\r\n",
        config.port
    )
    .and_then(|()| stream.flush())
    .map_err(|_| CdpError::Protocol)?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() as u64 >= MAX_HTTP_BYTES {
            return Err(CdpError::Protocol);
        }
        let mut byte = [0u8; 1];
        stream
            .read_exact(&mut byte)
            .map_err(|_| CdpError::Protocol)?;
        headers.push(byte[0]);
    }
    let headers =
        std::str::from_utf8(&headers[..headers.len() - 4]).map_err(|_| CdpError::Protocol)?;
    let mut lines = headers.split("\r\n");
    if !matches!(lines.next(), Some("HTTP/1.1 200 OK" | "HTTP/1.0 200 OK")) {
        return Err(CdpError::Protocol);
    }
    let mut content_length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(CdpError::Protocol)?;
        if name.eq_ignore_ascii_case("transfer-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(CdpError::Protocol);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(CdpError::Protocol);
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| CdpError::Protocol)?,
            );
        }
    }
    let content_length = content_length
        .filter(|length| {
            *length as u64
                <= MAX_HTTP_BYTES.saturating_sub(headers.len() as u64 + b"\r\n\r\n".len() as u64)
        })
        .ok_or(CdpError::Protocol)?;
    let mut body = vec![0u8; content_length];
    stream
        .read_exact(&mut body)
        .map_err(|_| CdpError::Protocol)?;
    if body.len() != content_length {
        return Err(CdpError::Protocol);
    }
    let targets: Value = serde_json::from_slice(&body).map_err(|_| CdpError::Protocol)?;
    let mut matches = targets
        .as_array()
        .ok_or(CdpError::Protocol)?
        .iter()
        .filter(|target| target.get("id").and_then(Value::as_str) == Some(&config.target_id));
    let target = matches.next().ok_or(CdpError::TargetNotFound)?;
    if matches.next().is_some()
        || !matches!(
            target.get("type").and_then(Value::as_str),
            Some("page" | "webview")
        )
    {
        return Err(CdpError::Protocol);
    }
    let websocket_url = target
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .ok_or(CdpError::Protocol)?;
    validate_websocket_url(config, websocket_url)
}

fn validate_websocket_url(config: &CdpConfig, websocket_url: &str) -> Result<String, CdpError> {
    let expected = format!(
        "ws://127.0.0.1:{}/devtools/page/{}",
        config.port, config.target_id
    );
    if websocket_url != expected {
        return Err(CdpError::InvalidConfig);
    }
    Ok(expected)
}

fn set_stream_deadline(stream: &TcpStream, deadline_at_ms: i64) -> std::io::Result<()> {
    let remaining = deadline_at_ms.saturating_sub(now_ms());
    if remaining <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "deadline expired",
        ));
    }
    let timeout =
        Duration::from_millis(u64::try_from(remaining).unwrap_or(u64::MAX)).min(MAX_IO_TIMEOUT);
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

fn border_quad(response: &Value) -> Result<[f64; 8], DispatchError> {
    let values = response
        .pointer("/model/border")
        .and_then(Value::as_array)
        .ok_or_else(|| no_effect("browser target has no stable box"))?;
    let mut quad = [0.0; 8];
    if values.len() != quad.len() {
        return Err(no_effect("browser target has no stable box"));
    }
    for (output, value) in quad.iter_mut().zip(values) {
        *output = value
            .as_f64()
            .filter(|number| number.is_finite())
            .ok_or_else(|| no_effect("browser target has no stable box"))?;
    }
    Ok(quad)
}

fn viewport_point(quad: &[f64; 8], layout: &Value) -> Result<(i64, i64), DispatchError> {
    let viewport = layout
        .get("cssVisualViewport")
        .or_else(|| layout.get("visualViewport"))
        .ok_or_else(|| no_effect("browser viewport is unavailable"))?;
    let page_x = viewport.get("pageX").and_then(Value::as_f64).unwrap_or(0.0);
    let page_y = viewport.get("pageY").and_then(Value::as_f64).unwrap_or(0.0);
    let width = viewport
        .get("clientWidth")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| no_effect("browser viewport is unavailable"))?;
    let height = viewport
        .get("clientHeight")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| no_effect("browser viewport is unavailable"))?;
    for index in (0..8).step_by(2) {
        let x = quad[index] - page_x;
        let y = quad[index + 1] - page_y;
        if !(0.0..width).contains(&x) || !(0.0..height).contains(&y) {
            return Err(no_effect("browser target is outside the viewport"));
        }
    }
    let x = ((quad[0] + quad[2] + quad[4] + quad[6]) / 4.0 - page_x).round();
    let y = ((quad[1] + quad[3] + quad[5] + quad[7]) / 4.0 - page_y).round();
    if !(0.0..width).contains(&x) || !(0.0..height).contains(&y) {
        return Err(no_effect("browser target is outside the viewport"));
    }
    Ok((x as i64, y as i64))
}

fn scroll_direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Up => "up",
        Direction::Down => "down",
        Direction::Left => "left",
        Direction::Right => "right",
    }
}

fn scroll_axis_delta(direction: Direction) -> (&'static str, i64) {
    match direction {
        Direction::Up => ("y", -SCROLL_DELTA_CSS_PX),
        Direction::Down => ("y", SCROLL_DELTA_CSS_PX),
        Direction::Left => ("x", -SCROLL_DELTA_CSS_PX),
        Direction::Right => ("x", SCROLL_DELTA_CSS_PX),
    }
}

fn verify_process(config: &CdpConfig) -> Result<(), CdpError> {
    if matches!(
        live_process_generation(config.browser_process_id),
        Ok(ref live) if live == &config.process_generation
    ) {
        Ok(())
    } else {
        Err(CdpError::StaleTarget)
    }
}

fn verify_endpoint_owner(config: &CdpConfig) -> Result<(), CdpError> {
    verify_process(config)?;
    let owners = endpoint_owner_process_ids(config.port, config.browser_process_id)?;
    if !endpoint_is_exclusively_owned_by(&owners, config.browser_process_id) {
        return Err(CdpError::StaleTarget);
    }
    verify_process(config)
}

fn endpoint_is_exclusively_owned_by(owners: &BTreeSet<u32>, process_id: u32) -> bool {
    owners.len() == 1 && owners.contains(&process_id)
}

#[cfg(target_os = "linux")]
fn endpoint_owner_process_ids(port: u16, process_id: u32) -> Result<BTreeSet<u32>, CdpError> {
    let table = std::fs::read_to_string(format!("/proc/{process_id}/net/tcp"))
        .map_err(|_| CdpError::StaleTarget)?;
    let expected_endpoint = format!("0100007F:{port:04X}");
    let mut inodes = BTreeSet::new();
    for line in table.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            return Err(CdpError::Protocol);
        }
        if fields[1] == expected_endpoint && fields[3] == "0A" {
            let inode = fields[9]
                .parse::<u64>()
                .ok()
                .filter(|inode| *inode > 0)
                .ok_or(CdpError::Protocol)?;
            inodes.insert(inode);
        }
    }
    if inodes.len() != 1 {
        return Ok(BTreeSet::new());
    }
    let socket = format!("socket:[{}]", inodes.first().ok_or(CdpError::Protocol)?);
    let mut owners = BTreeSet::new();
    for entry in std::fs::read_dir("/proc").map_err(|_| CdpError::StaleTarget)? {
        let entry = entry.map_err(|_| CdpError::StaleTarget)?;
        let Some(process_id) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let descriptors = match std::fs::read_dir(entry.path().join("fd")) {
            Ok(descriptors) => descriptors,
            Err(_) => continue,
        };
        for descriptor in descriptors.flatten() {
            if std::fs::read_link(descriptor.path())
                .ok()
                .is_some_and(|target| target == std::path::Path::new(&socket))
            {
                owners.insert(process_id);
                break;
            }
        }
    }
    Ok(owners)
}

#[cfg(target_os = "macos")]
fn endpoint_owner_process_ids(port: u16, _process_id: u32) -> Result<BTreeSet<u32>, CdpError> {
    const MAX_PROCESS_COUNT: usize = 1024 * 1024;
    const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
    const SOCKET_INFO_BYTES: usize = 792;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const SOCKINFO_TCP: i32 = 2;
    const TCP_LISTEN: i32 = 1;

    let capacity = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let capacity = usize::try_from(capacity)
        .ok()
        .filter(|count| *count > 0 && *count <= MAX_PROCESS_COUNT)
        .ok_or(CdpError::StaleTarget)?
        .saturating_add(64)
        .min(MAX_PROCESS_COUNT);
    let mut process_ids = vec![0i32; capacity];
    let buffer_bytes = process_ids
        .len()
        .checked_mul(std::mem::size_of::<i32>())
        .and_then(|bytes| i32::try_from(bytes).ok())
        .ok_or(CdpError::StaleTarget)?;
    let count = unsafe { libc::proc_listallpids(process_ids.as_mut_ptr().cast(), buffer_bytes) };
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count < process_ids.len())
        .ok_or(CdpError::StaleTarget)?;
    let mut owners = BTreeSet::new();
    for process_id in process_ids.into_iter().take(count).filter(|id| *id > 0) {
        let descriptor_bytes = unsafe {
            libc::proc_pidinfo(
                process_id,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        let Ok(descriptor_bytes) = usize::try_from(descriptor_bytes) else {
            continue;
        };
        if descriptor_bytes == 0 || descriptor_bytes > MAX_DESCRIPTOR_BYTES {
            continue;
        }
        let descriptor_capacity = descriptor_bytes
            .checked_add(64 * 8)
            .filter(|bytes| *bytes <= MAX_DESCRIPTOR_BYTES)
            .ok_or(CdpError::StaleTarget)?;
        let mut descriptors = vec![0u8; descriptor_capacity];
        let requested = i32::try_from(descriptors.len()).map_err(|_| CdpError::StaleTarget)?;
        let written = unsafe {
            libc::proc_pidinfo(
                process_id,
                libc::PROC_PIDLISTFDS,
                0,
                descriptors.as_mut_ptr().cast(),
                requested,
            )
        };
        let Ok(written) = usize::try_from(written) else {
            continue;
        };
        if written >= descriptors.len() || written % 8 != 0 {
            return Err(CdpError::StaleTarget);
        }
        for descriptor in descriptors[..written].chunks_exact(8) {
            let file_descriptor =
                i32::from_ne_bytes(descriptor[..4].try_into().map_err(|_| CdpError::Protocol)?);
            let descriptor_type = u32::from_ne_bytes(
                descriptor[4..8]
                    .try_into()
                    .map_err(|_| CdpError::Protocol)?,
            );
            if descriptor_type != libc::PROX_FDTYPE_SOCKET as u32 {
                continue;
            }
            let mut socket = [0u8; SOCKET_INFO_BYTES];
            let written = unsafe {
                libc::proc_pidfdinfo(
                    process_id,
                    file_descriptor,
                    PROC_PIDFDSOCKETINFO,
                    socket.as_mut_ptr().cast(),
                    SOCKET_INFO_BYTES as i32,
                )
            };
            if written != SOCKET_INFO_BYTES as i32
                || i32::from_ne_bytes(socket[256..260].try_into().unwrap_or_default())
                    != SOCKINFO_TCP
                || i32::from_ne_bytes(socket[344..348].try_into().unwrap_or_default()) != TCP_LISTEN
                || socket[288] & 1 == 0
                || socket[324..328] != Ipv4Addr::LOCALHOST.octets()
                || u16::from_be_bytes(socket[268..270].try_into().unwrap_or_default()) != port
            {
                continue;
            }
            owners.insert(u32::try_from(process_id).map_err(|_| CdpError::Protocol)?);
            break;
        }
    }
    Ok(owners)
}

#[cfg(windows)]
fn endpoint_owner_process_ids(port: u16, _process_id: u32) -> Result<BTreeSet<u32>, CdpError> {
    const AF_INET: u32 = 2;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
    const NO_ERROR: u32 = 0;
    const TCP_LISTEN: u32 = 2;
    const TCP_TABLE_OWNER_PID_LISTENER: i32 = 3;
    const TCP_ROW_BYTES: usize = 24;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut std::ffi::c_void,
            size: *mut u32,
            order: i32,
            family: u32,
            class: i32,
            reserved: u32,
        ) -> u32;
    }

    let mut size = 0u32;
    let initial = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    let size = usize::try_from(size)
        .ok()
        .filter(|size| *size >= 4 && *size <= MAX_TABLE_BYTES)
        .ok_or(CdpError::StaleTarget)?;
    if initial != ERROR_INSUFFICIENT_BUFFER && initial != NO_ERROR {
        return Err(CdpError::StaleTarget);
    }
    let mut table = vec![0u8; size];
    let mut written = u32::try_from(table.len()).map_err(|_| CdpError::StaleTarget)?;
    if unsafe {
        GetExtendedTcpTable(
            table.as_mut_ptr().cast(),
            &mut written,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    } != NO_ERROR
    {
        return Err(CdpError::StaleTarget);
    }
    let written = usize::try_from(written).map_err(|_| CdpError::StaleTarget)?;
    if written > table.len() || written < 4 {
        return Err(CdpError::Protocol);
    }
    let row_count =
        u32::from_ne_bytes(table[..4].try_into().map_err(|_| CdpError::Protocol)?) as usize;
    if 4usize
        .checked_add(
            row_count
                .checked_mul(TCP_ROW_BYTES)
                .ok_or(CdpError::Protocol)?,
        )
        .is_none_or(|required| required > written)
    {
        return Err(CdpError::Protocol);
    }
    let mut owners = BTreeSet::new();
    for row in table[4..].chunks_exact(TCP_ROW_BYTES).take(row_count) {
        if u32::from_ne_bytes(row[..4].try_into().map_err(|_| CdpError::Protocol)?) == TCP_LISTEN
            && row[4..8] == Ipv4Addr::LOCALHOST.octets()
            && u16::from_be_bytes(row[8..10].try_into().map_err(|_| CdpError::Protocol)?) == port
        {
            owners.insert(u32::from_ne_bytes(
                row[20..24].try_into().map_err(|_| CdpError::Protocol)?,
            ));
        }
    }
    Ok(owners)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn endpoint_owner_process_ids(_port: u16, _process_id: u32) -> Result<BTreeSet<u32>, CdpError> {
    Err(CdpError::Unsupported)
}

#[cfg(target_os = "linux")]
fn live_process_generation(process_id: u32) -> Result<String, CdpError> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| CdpError::StaleTarget)?;
    let boot_id = boot_id.trim();
    if boot_id.len() != 36
        || !boot_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(CdpError::StaleTarget);
    }
    let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat"))
        .map_err(|_| CdpError::StaleTarget)?;
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or(CdpError::StaleTarget)?;
    let start_ticks = fields
        .split_whitespace()
        .nth(19)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(CdpError::StaleTarget)?;
    let generation =
        semantic_fingerprint(&(boot_id, start_ticks)).map_err(|_| CdpError::Protocol)?;
    Ok(format!("linux-{generation}"))
}

#[cfg(target_os = "macos")]
fn live_process_generation(process_id: u32) -> Result<String, CdpError> {
    let process_id = i32::try_from(process_id).map_err(|_| CdpError::InvalidConfig)?;
    let mut information = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let written = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut information as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if written != size || information.pbi_start_tvsec == 0 {
        return Err(CdpError::StaleTarget);
    }
    Ok(format!(
        "macos-{}-{}",
        information.pbi_start_tvsec, information.pbi_start_tvusec
    ))
}

#[cfg(windows)]
fn live_process_generation(process_id: u32) -> Result<String, CdpError> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) }
        .map_err(|_| CdpError::StaleTarget)?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let succeeded =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
            .is_ok();
    let _ = unsafe { CloseHandle(process) };
    if !succeeded {
        return Err(CdpError::StaleTarget);
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    Ok(format!("windows-{value}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn live_process_generation(_process_id: u32) -> Result<String, CdpError> {
    Err(CdpError::Unsupported)
}

fn root_backend_node_ids(snapshot: &Value, root_frame_id: &str) -> Result<BTreeSet<u64>, CdpError> {
    let strings = snapshot.get("strings").and_then(Value::as_array);
    let mut documents = snapshot
        .get("documents")
        .and_then(Value::as_array)
        .ok_or(CdpError::Protocol)?
        .iter()
        .filter(|document| {
            document.get("frameId").is_some_and(|frame_id| {
                frame_id.as_str() == Some(root_frame_id)
                    || frame_id
                        .as_u64()
                        .and_then(|index| usize::try_from(index).ok())
                        .and_then(|index| strings.and_then(|values| values.get(index)))
                        .and_then(Value::as_str)
                        == Some(root_frame_id)
            })
        });
    let document = documents.next().ok_or(CdpError::Protocol)?;
    if documents.next().is_some() {
        return Err(CdpError::Protocol);
    }
    document
        .pointer("/nodes/backendNodeId")
        .and_then(Value::as_array)
        .ok_or(CdpError::Protocol)?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|value| *value > 0)
                .ok_or(CdpError::Protocol)
        })
        .collect()
}

struct AxSemantics {
    role: String,
    name: Option<String>,
    protected: bool,
    visible: bool,
    enabled: bool,
    invokable: bool,
    editable: bool,
}

fn ax_semantics(node: &Value) -> Result<AxSemantics, CdpError> {
    let role = ax_value(node.get("role")).ok_or(CdpError::Protocol)?;
    if role.is_empty() || role == "none" {
        return Err(CdpError::Protocol);
    }
    let protected = ax_bool_property(node, "protected").unwrap_or(false);
    let name = if protected {
        Some("[redacted]".to_string())
    } else {
        ax_value(node.get("name"))
    };
    let hidden = ax_bool_property(node, "hidden").unwrap_or(false);
    let disabled = ax_bool_property(node, "disabled").unwrap_or(false);
    let readonly = ax_bool_property(node, "readonly").unwrap_or(false);
    let editable = !readonly
        && (ax_property(node, "editable").is_some()
            || matches!(role.as_str(), "textbox" | "searchbox"));
    let invokable = matches!(
        role.as_str(),
        "button"
            | "checkbox"
            | "link"
            | "menuitem"
            | "menuitemcheckbox"
            | "menuitemradio"
            | "option"
            | "radio"
            | "switch"
            | "tab"
            | "treeitem"
    );
    Ok(AxSemantics {
        role,
        name,
        protected,
        visible: !hidden,
        enabled: !disabled,
        invokable,
        editable,
    })
}

fn live_ax_semantics(tree: &Value, backend_node_id: u64) -> Result<AxSemantics, DispatchError> {
    let mut nodes = tree
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| no_effect("browser target changed"))?
        .iter()
        .filter(|node| {
            node.get("backendDOMNodeId").and_then(Value::as_u64) == Some(backend_node_id)
                && node.get("ignored").and_then(Value::as_bool) != Some(true)
        });
    let node = nodes
        .next()
        .ok_or_else(|| no_effect("browser target changed"))?;
    if nodes.next().is_some() {
        return Err(no_effect("browser target is ambiguous"));
    }
    ax_semantics(node).map_err(|_| no_effect("browser target changed"))
}

fn parse_ax_tree(
    tree: &Value,
    observation_id: &str,
    document_id: &str,
    root_backend_node_ids: &BTreeSet<u64>,
) -> Result<(Vec<SemanticElement>, BTreeMap<String, CdpNode>), CdpError> {
    let raw_nodes = tree
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or(CdpError::Protocol)?;
    if raw_nodes.len() > MAX_SEMANTIC_ELEMENTS {
        return Err(CdpError::Protocol);
    }
    let mut parents = BTreeMap::new();
    let mut selected = Vec::new();
    let mut backend_ids = BTreeSet::new();
    for raw in raw_nodes {
        let raw_id = required_string(raw, "nodeId")?;
        if let Some(parent_id) = raw.get("parentId").and_then(Value::as_str) {
            parents.insert(raw_id.to_string(), parent_id.to_string());
        }
        if raw.get("ignored").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(backend_node_id) = raw.get("backendDOMNodeId").and_then(Value::as_u64) else {
            continue;
        };
        if !root_backend_node_ids.contains(&backend_node_id) {
            continue;
        }
        if backend_node_id == 0 || !backend_ids.insert(backend_node_id) {
            return Err(CdpError::Protocol);
        }
        let role = ax_value(raw.get("role")).ok_or(CdpError::Protocol)?;
        if role.is_empty() || role == "none" {
            continue;
        }
        let semantics = ax_semantics(raw)?;
        selected.push((raw_id.to_string(), backend_node_id, semantics));
    }

    let selected_ids = selected
        .iter()
        .map(|(raw_id, ..)| raw_id.clone())
        .collect::<BTreeSet<_>>();
    let mut opaque_ids = BTreeMap::new();
    for (raw_id, backend_node_id, ..) in &selected {
        let element_id = opaque_element_id(observation_id, &backend_node_id.to_string())
            .map_err(|_| CdpError::Protocol)?;
        opaque_ids.insert(raw_id.clone(), element_id);
    }

    let mut elements = Vec::with_capacity(selected.len());
    let mut nodes = BTreeMap::new();
    for (index, (raw_id, backend_node_id, semantics)) in selected.into_iter().enumerate() {
        let mut parent = parents.get(&raw_id).map(String::as_str);
        while parent.is_some_and(|id| !selected_ids.contains(id)) {
            parent = parent.and_then(|id| parents.get(id).map(String::as_str));
        }
        let parent_id = parent.and_then(|id| opaque_ids.get(id)).cloned();
        let element_id = opaque_ids
            .get(raw_id.as_str())
            .cloned()
            .ok_or(CdpError::Protocol)?;
        let fingerprint_hash = semantic_fingerprint(&(
            document_id,
            backend_node_id,
            semantics.role.as_str(),
            semantics.name.as_deref(),
        ))
        .map_err(|_| CdpError::Protocol)?;
        let element = SemanticElement {
            tag: semantic_tag(index).map_err(|_| CdpError::Protocol)?,
            element_id: element_id.clone(),
            parent_id,
            fingerprint_hash,
            role: semantics.role.clone(),
            name: semantics.name.clone(),
            bounds: None,
            actionability: Actionability {
                visible: semantics.visible,
                enabled: semantics.enabled,
                unambiguous: true,
                stable: false,
                receives_events: false,
                invokable: semantics.invokable,
                editable: semantics.editable,
            },
        };
        nodes.insert(
            element_id,
            CdpNode {
                backend_node_id,
                protected: semantics.protected,
                element: element.clone(),
            },
        );
        elements.push(element);
    }
    Ok((elements, nodes))
}

fn ax_property<'a>(node: &'a Value, name: &str) -> Option<&'a Value> {
    node.get("properties")?
        .as_array()?
        .iter()
        .find_map(|value| {
            (value.get("name")?.as_str()? == name)
                .then(|| value.get("value"))
                .flatten()
        })
}

fn ax_bool_property(node: &Value, name: &str) -> Option<bool> {
    ax_property(node, name)?.get("value")?.as_bool()
}

fn ax_value(value: Option<&Value>) -> Option<String> {
    value?.get("value")?.as_str().and_then(redacted_name)
}

fn redacted_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let value = value
        .chars()
        .filter(|character| !character.is_control())
        .take(1_024)
        .collect::<String>();
    (!value.is_empty()).then_some(value)
}

fn redacted_probe(mut value: Value, protected: bool) -> Value {
    if let Some(object) = value.as_object_mut() {
        for (from, to) in [
            ("valueHash", "value_hash"),
            ("valueLength", "value_length"),
            ("valueTooLarge", "value_too_large"),
        ] {
            if let Some(field) = object.remove(from) {
                if !protected {
                    object.insert(to.to_string(), field);
                }
            }
        }
    }
    value
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, CdpError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(CdpError::Protocol)
}

fn boundary(cancellation: &CancellationToken, deadline_at_ms: i64) -> Result<(), CdpError> {
    if cancellation.is_cancelled() {
        Err(CdpError::Cancelled)
    } else if now_ms() >= deadline_at_ms {
        Err(CdpError::Expired)
    } else {
        Ok(())
    }
}

fn check_effect_boundary(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), DispatchError> {
    if cancellation.is_cancelled() {
        Err(DispatchError {
            message: "browser effect cancelled before dispatch".to_string(),
            effect: EffectKnowledge::CancelledBeforeEffect,
            code: FailureCode::DispatchFailed,
        })
    } else if now_ms() >= deadline_at_ms {
        Err(DispatchError {
            message: "browser effect expired before dispatch".to_string(),
            effect: EffectKnowledge::ExpiredBeforeEffect,
            code: FailureCode::DispatchFailed,
        })
    } else {
        Ok(())
    }
}

fn check_after_effect_boundary(
    cancellation: &CancellationToken,
    deadline_at_ms: i64,
) -> Result<(), DispatchError> {
    if cancellation.is_cancelled() || now_ms() >= deadline_at_ms {
        Err(unknown(
            "browser effect completed at the cancellation or deadline boundary",
        ))
    } else {
        Ok(())
    }
}

fn map_semantic_error(error: SemanticError) -> CdpError {
    match error {
        SemanticError::TargetNotFound => CdpError::TargetNotFound,
        SemanticError::StaleObservation | SemanticError::StaleTarget => CdpError::StaleTarget,
        _ => CdpError::Protocol,
    }
}

fn map_cdp_protocol_error(error: CdpError) -> ProtocolError {
    match error {
        CdpError::Cancelled => ProtocolError::ObservationCancelled,
        CdpError::Expired => ProtocolError::ObservationExpired,
        CdpError::StaleTarget => ProtocolError::StaleTarget("browser target changed".to_string()),
        CdpError::TargetNotFound => {
            ProtocolError::TargetNotFound("browser target was not found".to_string())
        }
        _ => backend_error(),
    }
}

fn backend_error() -> ProtocolError {
    ProtocolError::Executor("browser backend operation failed".to_string())
}

fn no_effect(message: &str) -> DispatchError {
    DispatchError {
        message: message.to_string(),
        effect: EffectKnowledge::NoEffect,
        code: FailureCode::StaleTarget,
    }
}

fn unknown(message: &str) -> DispatchError {
    DispatchError {
        message: message.to_string(),
        effect: EffectKnowledge::Unknown,
        code: FailureCode::DispatchFailed,
    }
}

fn unsupported() -> DispatchError {
    DispatchError {
        message: "browser action is unsupported".to_string(),
        effect: EffectKnowledge::NoEffect,
        code: FailureCode::Unsupported,
    }
}

fn success_receipt() -> DispatchReceipt {
    DispatchReceipt {
        backend: BACKEND_NAME.to_string(),
        fallback_chain: Vec::new(),
    }
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::{
        AckState, ActionRequest, AuthorityGrant, AuthorityVerifier, Engine, InteractionMode,
        SafetyClass, SignedAuthority, Terminal, VerifiedAuthority,
    };

    struct FakeChannel {
        endpoint: SocketAddr,
        target_id: String,
        methods: Vec<String>,
        parameters: Vec<Value>,
        responses: VecDeque<Result<Value, CdpChannelError>>,
        delay_ms: u64,
        cancellation: Option<CancellationToken>,
    }

    impl CdpChannel for FakeChannel {
        fn endpoint(&self) -> SocketAddr {
            self.endpoint
        }

        fn target_id(&self) -> &str {
            &self.target_id
        }

        fn command(
            &mut self,
            method: &str,
            parameters: Value,
            _deadline_at_ms: i64,
        ) -> Result<Value, CdpChannelError> {
            self.methods.push(method.to_string());
            self.parameters.push(parameters);
            if self.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.delay_ms));
            }
            if let Some(cancellation) = &self.cancellation {
                cancellation.cancel();
            }
            self.responses
                .pop_front()
                .unwrap_or(Err(CdpChannelError::BeforeSend))
        }
    }

    fn config() -> CdpConfig {
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        CdpConfig::localhost(9222, "page-1", process_id, process_generation).expect("config")
    }

    fn channel() -> FakeChannel {
        editable_channel(true)
    }

    fn editable_channel(protected: bool) -> FakeChannel {
        FakeChannel {
            endpoint: config().endpoint(),
            target_id: "page-1".to_string(),
            methods: Vec::new(),
            parameters: Vec::new(),
            delay_ms: 0,
            cancellation: None,
            responses: VecDeque::from(
                [
                    json!({"targetInfo":{"targetId":"page-1","type":"page"}}),
                    json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}}),
                    json!({"executionContextId":9}),
                    viewport(),
                    json!({"documents":[
                        {"frameId":"frame-1","nodes":{"backendNodeId":[7]}},
                        {"frameId":"child-frame","nodes":{"backendNodeId":[8]}}
                    ]}),
                    json!({"nodes":[{
                        "nodeId":"ax-1",
                        "backendDOMNodeId":7,
                        "role":{"value":"textbox"},
                        "name":{"value":"secret"},
                        "properties":[
                            {"name":"protected","value":{"value":protected}},
                            {"name":"editable","value":{"value":"plaintext"}}
                        ]
                    }]}),
                    json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}}),
                ]
                .map(Ok),
            ),
        }
    }

    fn button_channel() -> FakeChannel {
        FakeChannel {
            endpoint: config().endpoint(),
            target_id: "page-1".to_string(),
            methods: Vec::new(),
            parameters: Vec::new(),
            delay_ms: 0,
            cancellation: None,
            responses: VecDeque::from(
                [
                    json!({"targetInfo":{"targetId":"page-1","type":"page"}}),
                    json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}}),
                    json!({"executionContextId":9}),
                    viewport(),
                    json!({"documents":[
                        {"frameId":"frame-1","nodes":{"backendNodeId":[7]}},
                        {"frameId":"child-frame","nodes":{"backendNodeId":[8]}}
                    ]}),
                    json!({"nodes":[
                        {
                            "nodeId":"ax-1",
                            "backendDOMNodeId":7,
                            "role":{"value":"button"},
                            "name":{"value":"Submit"}
                        },
                        {
                            "nodeId":"ax-child",
                            "backendDOMNodeId":8,
                            "role":{"value":"button"},
                            "name":{"value":"Child"}
                        }
                    ]}),
                    json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}}),
                ]
                .map(Ok),
            ),
        }
    }

    fn scroll_channel() -> FakeChannel {
        let mut channel = button_channel();
        channel.responses[5] = Ok(json!({"nodes":[
            {
                "nodeId":"ax-1",
                "backendDOMNodeId":7,
                "role":{"value":"list"},
                "name":{"value":"Feed"}
            },
            {
                "nodeId":"ax-child",
                "backendDOMNodeId":8,
                "role":{"value":"listitem"},
                "name":{"value":"Entry"}
            }
        ]}));
        channel
    }

    fn viewport() -> Value {
        json!({"cssVisualViewport":{
            "pageX":0,
            "pageY":0,
            "clientWidth":800,
            "clientHeight":600,
            "scale":1
        }})
    }

    fn live_ax(role: &str, name: &str, protected: bool, properties: Value) -> Value {
        json!({"nodes":[{
            "nodeId":"live-ax",
            "backendDOMNodeId":7,
            "role":{"value":role},
            "name":{"value":name},
            "properties":[
                {"name":"protected","value":{"value":protected}},
                properties
            ]
        }]})
    }

    fn scroll_probe(down: bool) -> Value {
        json!({"result":{"value":{
            "connected":true,
            "visible":true,
            "enabled":true,
            "receives":true,
            "up":false,
            "down":down,
            "left":false,
            "right":false,
            "top":0,
            "leftOffset":0
        }}})
    }

    fn scroll_effect_result(eligible: bool, before: f64, intended: f64, after: f64) -> Value {
        json!({"result":{"value":{
            "eligible":eligible,
            "before":before,
            "intended":intended,
            "after":after
        }}})
    }

    fn invoke_pre_effect_responses(
        final_viewport: Value,
        final_ax: Value,
    ) -> Vec<Result<Value, CdpChannelError>> {
        vec![
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(json!({"object":{"objectId":"object-1"}})),
            Ok(json!({"result":{"value":{
                "connected":true,
                "visible":true,
                "enabled":true,
                "receives":true,
                "editable":false,
                "active":false,
                "valueHash":null,
                "valueLength":null,
                "valueTooLarge":false
            }}})),
            Ok(final_viewport),
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(final_ax),
        ]
    }

    fn scroll_pre_effect_responses(
        hit_backend_node_id: u64,
        final_ax: Value,
    ) -> Vec<Result<Value, CdpChannelError>> {
        vec![
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(json!({"object":{"objectId":"object-1"}})),
            Ok(scroll_probe(true)),
            Ok(json!({"model":{"border":[10,10,30,10,30,30,10,30]}})),
            Ok(json!({"result":{"value":true}})),
            Ok(json!({"model":{"border":[10,10,30,10,30,30,10,30]}})),
            Ok(viewport()),
            Ok(json!({"backendNodeId":hit_backend_node_id})),
            Ok(viewport()),
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(final_ax),
            Ok(scroll_probe(true)),
        ]
    }

    fn rejected_invoke(final_viewport: Value, final_ax: Value) -> (DispatchError, Vec<String>) {
        let executor = CdpExecutor::new(config(), button_channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        executor
            .channel
            .lock()
            .expect("channel")
            .responses
            .extend(invoke_pre_effect_responses(final_viewport, final_ax));
        let error = executor
            .dispatch(
                &Action::Invoke,
                &resolved,
                &VerificationPolicy::SnapshotChanged,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect_err("stale target");
        let methods = executor.channel.lock().expect("channel").methods.clone();
        (error, methods)
    }

    fn resolved_scroll() -> (CdpExecutor<FakeChannel>, ResolvedTarget) {
        let executor = CdpExecutor::new(config(), scroll_channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        (executor, resolved)
    }

    struct AllowAuthority;

    impl AuthorityVerifier for AllowAuthority {
        fn verify(
            &self,
            _request: &ActionRequest,
            _action_hash: &str,
        ) -> Result<VerifiedAuthority, ProtocolError> {
            Ok(VerifiedAuthority {
                expires_at_ms: i64::MAX,
            })
        }
    }

    fn probe(active: bool, value_hash: &str, value_length: usize) -> Value {
        json!({"result":{"value":{
            "connected":true,
            "visible":true,
            "enabled":true,
            "receives":true,
            "editable":true,
            "active":active,
            "valueHash":value_hash,
            "valueLength":value_length,
            "valueTooLarge":false
        }}})
    }

    fn live_shared_executor(
        mut channel: FakeChannel,
    ) -> (std::net::TcpListener, CdpExecutor<FakeChannel>) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("local address").port();
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        let config = CdpConfig::localhost(port, "page-1", process_id, process_generation)
            .expect("configuration");
        channel.endpoint = config.endpoint();
        let executor = CdpExecutor::new(config, channel).expect("executor");
        (listener, executor)
    }

    fn background_request(
        operation_id: &str,
        action: Action,
        verification: VerificationPolicy,
    ) -> ActionRequest {
        ActionRequest {
            protocol_version: PROTOCOL_VERSION,
            action_version: PROTOCOL_VERSION,
            target_version: PROTOCOL_VERSION,
            verification_version: PROTOCOL_VERSION,
            operation_id: operation_id.to_string(),
            subject: "subject".to_string(),
            session_id: "session".to_string(),
            authority: SignedAuthority {
                grant: AuthorityGrant {
                    protocol_version: PROTOCOL_VERSION,
                    issuer: "host".to_string(),
                    key_id: "key".to_string(),
                    operation_id: operation_id.to_string(),
                    subject: "subject".to_string(),
                    session_id: "session".to_string(),
                    risk: SafetyClass::Reversible,
                    expires_at_ms: i64::MAX,
                    policy_generation: "generation".to_string(),
                    action_hash: "0".repeat(64),
                },
                signature: "0".repeat(128),
            },
            action,
            target: TargetRef::Element {
                target: SemanticTargetRef {
                    observation_id: "1".repeat(64),
                    generation: 1,
                    provenance_hash: "2".repeat(64),
                    element_id: "3".repeat(64),
                    fingerprint_hash: "4".repeat(64),
                },
            },
            interaction_mode: InteractionMode::BackgroundOnly,
            deadline_at_ms: i64::MAX,
            verification,
            safety: SafetyClass::Reversible,
        }
    }

    #[test]
    fn only_exact_local_channel_is_accepted() {
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        assert!(matches!(
            CdpConfig::localhost(9222, "../page-1", process_id, process_generation),
            Err(CdpError::InvalidConfig)
        ));
        let mut channel = channel();
        channel.endpoint = SocketAddr::from(([127, 0, 0, 1], 9223));
        assert!(matches!(
            CdpExecutor::new(config(), channel),
            Err(CdpError::InvalidConfig)
        ));
        assert!(matches!(
            validate_websocket_url(&config(), "ws://127.0.0.1:9223/devtools/page/page-1"),
            Err(CdpError::InvalidConfig)
        ));
    }

    #[test]
    fn shared_desktop_background_actions_reject_before_cdp() {
        let value = "updated";
        for (operation_id, action, verification, channel) in [
            (
                "cdp-background-invoke",
                Action::Invoke,
                VerificationPolicy::SnapshotChanged,
                button_channel(),
            ),
            (
                "cdp-background-scroll",
                Action::Scroll {
                    direction: Direction::Down,
                    amount: 1,
                },
                VerificationPolicy::None,
                scroll_channel(),
            ),
            (
                "cdp-background-set-value",
                Action::SetValue {
                    value: value.to_string(),
                },
                VerificationPolicy::TargetValueHash {
                    sha256: hex::encode(Sha256::digest(value.as_bytes())),
                },
                editable_channel(false),
            ),
        ] {
            let (_listener, executor) = live_shared_executor(channel);
            executor
                .semantic_observation(&CancellationToken::default(), i64::MAX)
                .expect("observation");
            executor.channel.lock().expect("channel").methods.clear();
            let request = background_request(operation_id, action, verification);
            let directory = tempfile::tempdir().expect("temporary directory");
            let engine = Engine::new(
                executor,
                directory.path().join("ledger.jsonl"),
                AllowAuthority,
            );
            let report = engine
                .execute(&request, &CancellationToken::default())
                .expect("execution report");
            assert!(matches!(
                report.acknowledgements.last().map(|ack| &ack.state),
                Some(AckState::Terminal { terminal })
                    if matches!(terminal.as_ref(), Terminal::Rejected {
                        code: FailureCode::Unsupported,
                        ..
                    })
            ));
            assert!(
                engine
                    .executor
                    .channel
                    .lock()
                    .expect("channel")
                    .methods
                    .is_empty()
            );
        }
    }

    #[test]
    fn shared_desktop_is_default_and_host_isolation_is_explicit() {
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        let shared = CdpConfig::localhost(9222, "page-1", process_id, process_generation.clone())
            .expect("shared configuration");
        let isolated =
            CdpConfig::host_isolated_localhost(9222, "page-1", process_id, process_generation)
                .expect("isolated configuration");
        assert_eq!(shared.session_isolation(), SessionIsolation::SharedDesktop);
        assert_eq!(isolated.session_isolation(), SessionIsolation::HostIsolated);
        let channel = FakeChannel {
            endpoint: isolated.endpoint(),
            target_id: isolated.target_id().to_string(),
            methods: Vec::new(),
            parameters: Vec::new(),
            responses: VecDeque::new(),
            delay_ms: 0,
            cancellation: None,
        };
        let executor = CdpExecutor::new(isolated, channel).expect("isolated executor");
        assert_eq!(executor.session_isolation(), SessionIsolation::HostIsolated);
    }

    #[test]
    fn endpoint_owner_mismatch_is_rejected() {
        let process_id = std::process::id();
        assert!(!endpoint_is_exclusively_owned_by(
            &BTreeSet::from([process_id.saturating_add(1)]),
            process_id,
        ));
        assert!(!endpoint_is_exclusively_owned_by(
            &BTreeSet::from([process_id, process_id.saturating_add(1)]),
            process_id,
        ));
    }

    #[test]
    fn command_events_are_bounded_and_do_not_replace_responses() {
        assert_eq!(
            cdp_command_result(&json!({"method":"Page.frameNavigated","params":{}}), 7),
            Ok(None)
        );
        assert_eq!(
            cdp_command_result(&json!({"id":7,"result":{"value":1}}), 7),
            Ok(Some(json!({"value":1})))
        );
        assert_eq!(
            cdp_command_result(&json!({"id":8,"result":{}}), 7),
            Err(CdpChannelError::AfterSend)
        );
    }

    #[test]
    fn stale_process_generation_is_rejected() {
        let mut config = config();
        config.process_generation.push_str("-stale");
        assert!(matches!(
            verify_endpoint_owner(&config),
            Err(CdpError::StaleTarget)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn live_loopback_listener_is_bound_to_its_process() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("local address").port();
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        let config = CdpConfig::localhost(port, "page-1", process_id, process_generation)
            .expect("configuration");
        assert_eq!(
            endpoint_owner_process_ids(port, process_id).expect("endpoint owners"),
            BTreeSet::from([process_id])
        );
        verify_endpoint_owner(&config).expect("endpoint ownership");
        drop(listener);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn capabilities_never_advertise_click_and_follow_live_ownership() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("local address").port();
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        let config =
            CdpConfig::localhost(port, "page-1", process_id, process_generation).expect("config");
        let mut channel = button_channel();
        channel.endpoint = config.endpoint();
        let mut executor = CdpExecutor::new(config, channel).expect("executor");
        let capabilities = executor.capabilities().expect("capabilities");
        assert_eq!(capabilities.permissions.get("cdp"), Some(&false));
        assert_eq!(capabilities.permissions.get("root_frame_only"), Some(&true));
        assert!(capabilities.supported_actions.is_empty());
        assert!(capabilities.action_capabilities.is_empty());
        assert_eq!(capabilities.display_geometry_hash, "0".repeat(64));

        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let capabilities = executor.capabilities().expect("capabilities");
        assert_eq!(capabilities.permissions.get("cdp"), Some(&true));
        assert_eq!(
            capabilities.supported_actions,
            ["invoke", "scroll", "set_value"]
        );
        assert!(
            !capabilities
                .supported_actions
                .iter()
                .any(|action| action == "click")
        );
        assert_eq!(
            capabilities.display_geometry_hash,
            observation.provenance.display_geometry_hash
        );
        assert_eq!(
            capabilities.action_capabilities,
            [
                ActionCapability {
                    action: "invoke".to_string(),
                    delivery_route: DeliveryRoute::TargetAddressed,
                    background_support: BackgroundSupport::HostIsolatedOnly,
                },
                ActionCapability {
                    action: "scroll".to_string(),
                    delivery_route: DeliveryRoute::TargetAddressed,
                    background_support: BackgroundSupport::HostIsolatedOnly,
                },
                ActionCapability {
                    action: "set_value".to_string(),
                    delivery_route: DeliveryRoute::TargetAddressed,
                    background_support: BackgroundSupport::HostIsolatedOnly,
                },
            ]
        );

        let expires_at_ms = {
            let mut latest = executor.latest.write().expect("observation");
            let observation = &mut latest.as_mut().expect("observation").observation;
            let expires_at_ms = observation.expires_at_ms;
            observation.expires_at_ms = now_ms();
            expires_at_ms
        };
        let capabilities = executor.capabilities().expect("capabilities");
        assert!(capabilities.supported_actions.is_empty());
        assert_eq!(capabilities.display_geometry_hash, "0".repeat(64));
        executor
            .latest
            .write()
            .expect("observation")
            .as_mut()
            .expect("observation")
            .observation
            .expires_at_ms = expires_at_ms;

        drop(listener);
        let capabilities = executor.capabilities().expect("capabilities");
        assert_eq!(capabilities.permissions.get("cdp"), Some(&false));
        assert!(capabilities.supported_actions.is_empty());
        assert_eq!(capabilities.display_geometry_hash, "0".repeat(64));

        executor.config.process_generation.push_str("-stale");
        let capabilities = executor.capabilities().expect("capabilities");
        assert_eq!(capabilities.permissions.get("cdp"), Some(&false));
        assert!(capabilities.supported_actions.is_empty());
        assert_eq!(capabilities.display_geometry_hash, "0".repeat(64));
    }

    #[test]
    fn discovery_uses_content_length_without_waiting_for_close() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("local address").port();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("connection");
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).expect("request");
                request.push(byte[0]);
            }
            let body = format!(
                "[{{\"id\":\"page-1\",\"type\":\"page\",\"webSocketDebuggerUrl\":\"ws://127.0.0.1:{port}/devtools/page/page-1\"}}]"
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                body.len()
            )
            .expect("response");
            stream.flush().expect("response flush");
            release_receiver
                .recv_timeout(Duration::from_secs(5))
                .expect("release");
        });
        let process_id = std::process::id();
        let generation = CdpConfig::process_generation(process_id).expect("process generation");
        let config = CdpConfig::localhost(port, "page-1", process_id, generation).expect("config");
        assert_eq!(
            discover_websocket_url(&config).expect("websocket URL"),
            format!("ws://127.0.0.1:{port}/devtools/page/page-1")
        );
        release_sender.send(()).expect("release");
        server.join().expect("server");
    }

    #[test]
    fn root_document_accepts_cdp_string_indexes() {
        assert_eq!(
            root_backend_node_ids(
                &json!({
                    "strings":["unused","frame-1"],
                    "documents":[{
                        "frameId":1,
                        "nodes":{"backendNodeId":[7,9]}
                    }]
                }),
                "frame-1"
            )
            .expect("backend node IDs"),
            BTreeSet::from([7, 9])
        );
    }

    #[test]
    fn snapshot_redacts_protected_names_and_binds_generation() {
        let executor = CdpExecutor::new(config(), channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        assert_eq!(observation.elements.len(), 1);
        assert_eq!(observation.elements.len(), 1);
        assert_eq!(observation.elements[0].tag, "e0");
        assert_eq!(observation.elements[0].name.as_deref(), Some("[redacted]"));
        assert!(observation.elements[0].actionability.editable);
        assert!(!observation.elements[0].actionability.stable);
        assert!(!observation.elements[0].actionability.receives_events);
        let target = observation.target("e0").expect("target");
        assert!(matches!(
            executor.engine_target(&target, now_ms()),
            Ok(TargetRef::Element { .. })
        ));
    }

    #[test]
    fn probe_hashes_values_before_returning_state() {
        assert!(!PROBE_FUNCTION.contains("crypto.subtle"));
        let probe = redacted_probe(
            json!({
                "connected":true,
                "valueHash":"9".repeat(64),
                "valueLength":10,
                "valueTooLarge":false
            }),
            false,
        );
        assert!(probe.get("value").is_none());
        assert_eq!(
            probe
                .get("value_hash")
                .and_then(Value::as_str)
                .map(str::len),
            Some(64)
        );
        let protected = redacted_probe(
            json!({
                "connected":true,
                "valueHash":"9".repeat(64),
                "valueLength":10,
                "valueTooLarge":false
            }),
            true,
        );
        assert!(protected.get("value_hash").is_none());
        assert!(protected.get("value_length").is_none());
    }

    #[test]
    fn protected_observation_drops_backend_value_fingerprints() {
        let executor = CdpExecutor::new(config(), channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        executor.channel.lock().expect("channel").responses.extend([
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(json!({"object":{"objectId":"object-1"}})),
            Ok(probe(false, &"9".repeat(64), 12)),
            Ok(viewport()),
            Ok(live_ax(
                "textbox",
                "secret",
                true,
                json!({"name":"editable","value":{"value":"plaintext"}}),
            )),
        ]);
        let observed = executor
            .observe(&TargetRef::Element { target })
            .expect("target observation");
        assert!(observed.state.get("value_hash").is_none());
        assert!(observed.state.get("value_length").is_none());
        assert!(observed.state.get("value_too_large").is_none());
    }

    #[test]
    fn target_observation_rejects_changed_live_accessibility_fingerprint() {
        let executor = CdpExecutor::new(config(), channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        executor.channel.lock().expect("channel").responses.extend([
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(json!({"object":{"objectId":"object-1"}})),
            Ok(probe(false, &"9".repeat(64), 12)),
            Ok(viewport()),
            Ok(live_ax(
                "button",
                "Changed",
                false,
                json!({"name":"focusable","value":{"value":true}}),
            )),
        ]);

        assert!(matches!(
            executor.observe(&TargetRef::Element { target }),
            Err(ProtocolError::StaleTarget(_))
        ));
    }

    #[test]
    fn target_observation_preserves_cancelled_and_expired_boundaries() {
        let executor = CdpExecutor::new(config(), channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let cancellation = CancellationToken::default();
        {
            let mut channel = executor.channel.lock().expect("channel");
            channel.cancellation = Some(cancellation.clone());
            channel
                .responses
                .push_back(Err(CdpChannelError::BeforeSend));
        }
        assert!(matches!(
            executor.observe_with_boundary(
                &TargetRef::Element {
                    target: target.clone(),
                },
                &cancellation,
                i64::MAX,
            ),
            Err(ProtocolError::ObservationCancelled)
        ));

        let active = CancellationToken::default();
        {
            let mut channel = executor.channel.lock().expect("channel");
            channel.cancellation = None;
            channel.delay_ms = 5;
            channel
                .responses
                .push_back(Err(CdpChannelError::BeforeSend));
        }
        assert!(matches!(
            executor.observe_with_boundary(
                &TargetRef::Element { target },
                &active,
                now_ms().saturating_add(1),
            ),
            Err(ProtocolError::ObservationExpired)
        ));
    }

    #[test]
    fn click_is_rejected_before_any_cdp_command() {
        let executor = CdpExecutor::new(config(), button_channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        let mut channel = executor.channel.lock().expect("channel");
        channel.methods.clear();
        channel.parameters.clear();
        drop(channel);
        let error = executor
            .dispatch(
                &Action::Click {
                    button: crate::MouseButton::Left,
                    count: 1,
                    allow_coordinate_fallback: false,
                },
                &resolved,
                &VerificationPolicy::SnapshotChanged,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect_err("click unsupported");
        let channel = executor.channel.lock().expect("channel");
        assert!(matches!(error.code, FailureCode::Unsupported));
        assert!(channel.methods.is_empty());
        assert!(!INVOKE_EFFECT_FUNCTION.contains("dispatchMouseEvent"));
    }

    #[test]
    fn invoke_uses_only_the_exact_object_bound_effect() {
        let executor = CdpExecutor::new(config(), button_channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        let mut channel = executor.channel.lock().expect("channel");
        channel.responses.extend(invoke_pre_effect_responses(
            viewport(),
            live_ax("button", "Submit", false, json!({})),
        ));
        channel
            .responses
            .push_back(Ok(json!({"result":{"value":{"eligible":true}}})));
        drop(channel);
        executor
            .dispatch(
                &Action::Invoke,
                &resolved,
                &VerificationPolicy::SnapshotChanged,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect("invoke");
        let channel = executor.channel.lock().expect("channel");
        assert!(
            !channel
                .methods
                .iter()
                .any(|method| method.starts_with("Input."))
        );
        assert!(!channel.methods.iter().any(|method| method == "DOM.focus"));
        assert_eq!(
            &channel.methods[7..],
            [
                "Page.getFrameTree",
                "DOM.resolveNode",
                "Runtime.callFunctionOn",
                "Page.getLayoutMetrics",
                "Page.getFrameTree",
                "Accessibility.getPartialAXTree",
                "Runtime.callFunctionOn",
            ]
        );
        let effect = channel.parameters.last().expect("effect parameters");
        assert_eq!(
            effect.get("objectId").and_then(Value::as_str),
            Some("object-1")
        );
        assert_eq!(
            effect.get("functionDeclaration").and_then(Value::as_str),
            Some(INVOKE_EFFECT_FUNCTION)
        );
    }

    #[test]
    fn invoke_post_send_failure_is_unknown() {
        let executor = CdpExecutor::new(config(), button_channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        let mut channel = executor.channel.lock().expect("channel");
        channel.responses.extend(invoke_pre_effect_responses(
            viewport(),
            live_ax("button", "Submit", false, json!({})),
        ));
        channel.responses.push_back(Err(CdpChannelError::AfterSend));
        drop(channel);
        let error = executor
            .dispatch(
                &Action::Invoke,
                &resolved,
                &VerificationPolicy::SnapshotChanged,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect_err("unknown invoke");
        assert_eq!(error.effect, EffectKnowledge::Unknown);
    }

    #[test]
    fn invoke_rejects_live_identity_geometry_and_actionability_drift() {
        let changed_viewport = json!({"cssVisualViewport":{
            "pageX":0,
            "pageY":0,
            "clientWidth":799,
            "clientHeight":600,
            "scale":1
        }});
        for (final_viewport, final_ax) in [
            (viewport(), live_ax("button", "Cancel", false, json!({}))),
            (
                viewport(),
                live_ax(
                    "button",
                    "Submit",
                    false,
                    json!({"name":"disabled","value":{"value":true}}),
                ),
            ),
            (
                changed_viewport,
                live_ax("button", "Submit", false, json!({})),
            ),
        ] {
            let (error, methods) = rejected_invoke(final_viewport, final_ax);
            assert_eq!(error.effect, EffectKnowledge::NoEffect);
            assert!(!methods.iter().any(|method| method.starts_with("Input.")));
            assert_ne!(
                methods.last().map(String::as_str),
                Some("Runtime.callFunctionOn")
            );
        }
    }

    #[test]
    fn scroll_updates_only_the_exact_resolved_node_once() {
        let (executor, resolved) = resolved_scroll();
        let mut channel = executor.channel.lock().expect("channel");
        channel.responses.extend(scroll_pre_effect_responses(
            7,
            live_ax("list", "Feed", false, json!({})),
        ));
        channel
            .responses
            .push_back(Ok(scroll_effect_result(true, 0.0, 100.0, 100.0)));
        drop(channel);

        executor
            .dispatch(
                &Action::Scroll {
                    direction: Direction::Down,
                    amount: 1,
                },
                &resolved,
                &VerificationPolicy::None,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect("scroll");
        let channel = executor.channel.lock().expect("channel");
        assert!(
            !channel
                .methods
                .iter()
                .any(|method| method.starts_with("Input."))
        );
        assert!(
            !channel
                .methods
                .iter()
                .any(|method| method == "Target.activateTarget")
        );
        assert_eq!(
            channel.methods.last().map(String::as_str),
            Some("Runtime.callFunctionOn")
        );
        let effect = channel.parameters.last().expect("effect parameters");
        assert_eq!(
            effect.get("functionDeclaration").and_then(Value::as_str),
            Some(SCROLL_EFFECT_FUNCTION)
        );
        assert_eq!(
            effect.pointer("/arguments/0/value").and_then(Value::as_str),
            Some("y")
        );
        assert_eq!(
            effect.pointer("/arguments/1/value").and_then(Value::as_i64),
            Some(100)
        );
    }

    #[test]
    fn scroll_offsets_are_direction_specific() {
        assert_eq!(scroll_axis_delta(Direction::Up), ("y", -100));
        assert_eq!(scroll_axis_delta(Direction::Down), ("y", 100));
        assert_eq!(scroll_axis_delta(Direction::Left), ("x", -100));
        assert_eq!(scroll_axis_delta(Direction::Right), ("x", 100));
    }

    #[test]
    fn scroll_rejects_alternate_and_stale_targets_before_effect() {
        for (hit_backend_node_id, final_ax) in [
            (8, live_ax("list", "Feed", false, json!({}))),
            (7, live_ax("list", "Other", false, json!({}))),
        ] {
            let (executor, resolved) = resolved_scroll();
            executor
                .channel
                .lock()
                .expect("channel")
                .responses
                .extend(scroll_pre_effect_responses(hit_backend_node_id, final_ax));
            let error = executor
                .dispatch(
                    &Action::Scroll {
                        direction: Direction::Down,
                        amount: 1,
                    },
                    &resolved,
                    &VerificationPolicy::None,
                    &CancellationToken::default(),
                    i64::MAX,
                )
                .expect_err("rejected scroll");
            assert_eq!(error.effect, EffectKnowledge::NoEffect);
            assert!(
                !executor
                    .channel
                    .lock()
                    .expect("channel")
                    .parameters
                    .iter()
                    .any(|parameters| parameters
                        .get("functionDeclaration")
                        .and_then(Value::as_str)
                        == Some(SCROLL_EFFECT_FUNCTION))
            );
        }
    }

    #[test]
    fn scroll_mismatch_and_post_send_failure_are_unknown() {
        for effect in [
            Ok(scroll_effect_result(true, 0.0, 100.0, 0.0)),
            Err(CdpChannelError::AfterSend),
        ] {
            let (executor, resolved) = resolved_scroll();
            let mut channel = executor.channel.lock().expect("channel");
            channel.responses.extend(scroll_pre_effect_responses(
                7,
                live_ax("list", "Feed", false, json!({})),
            ));
            channel.responses.push_back(effect);
            drop(channel);
            let error = executor
                .dispatch(
                    &Action::Scroll {
                        direction: Direction::Down,
                        amount: 1,
                    },
                    &resolved,
                    &VerificationPolicy::None,
                    &CancellationToken::default(),
                    i64::MAX,
                )
                .expect_err("unknown scroll");
            assert_eq!(error.effect, EffectKnowledge::Unknown);
        }
    }

    #[test]
    fn scroll_rejects_repetition_and_caller_verification_before_queries() {
        for (amount, verification) in [
            (2, VerificationPolicy::None),
            (1, VerificationPolicy::SnapshotChanged),
        ] {
            let (executor, resolved) = resolved_scroll();
            let mut channel = executor.channel.lock().expect("channel");
            channel.methods.clear();
            channel.parameters.clear();
            drop(channel);
            let error = executor
                .dispatch(
                    &Action::Scroll {
                        direction: Direction::Down,
                        amount,
                    },
                    &resolved,
                    &verification,
                    &CancellationToken::default(),
                    i64::MAX,
                )
                .expect_err("unsupported scroll");
            assert!(matches!(error.code, FailureCode::Unsupported));
            assert!(executor.channel.lock().expect("channel").methods.is_empty());
        }
    }

    #[test]
    fn set_value_post_send_failure_is_unknown() {
        let executor = CdpExecutor::new(config(), channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        let probe = json!({"result":{"value":{
            "connected":true,
            "visible":true,
            "enabled":true,
            "receives":true,
            "editable":true,
            "active":false,
            "valueHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "valueLength":0,
            "valueTooLarge":false
        }}});
        let mut channel = executor.channel.lock().expect("channel");
        channel.responses.extend([
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(json!({"object":{"objectId":"object-1"}})),
            Ok(probe),
            Ok(viewport()),
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(live_ax(
                "textbox",
                "secret",
                true,
                json!({"name":"editable","value":{"value":"plaintext"}}),
            )),
            Err(CdpChannelError::AfterSend),
        ]);
        drop(channel);

        let error = executor
            .dispatch(
                &Action::SetValue {
                    value: "updated".to_string(),
                },
                &resolved,
                &VerificationPolicy::SnapshotChanged,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect_err("editing failure");
        assert_eq!(error.effect, EffectKnowledge::Unknown);
        assert_eq!(
            &executor.channel.lock().expect("channel").methods[7..],
            [
                "Page.getFrameTree",
                "DOM.resolveNode",
                "Runtime.callFunctionOn",
                "Page.getLayoutMetrics",
                "Page.getFrameTree",
                "Accessibility.getPartialAXTree",
                "Runtime.callFunctionOn",
            ]
        );
    }

    #[test]
    fn set_value_uses_one_target_bound_effect_without_global_input() {
        let executor = CdpExecutor::new(config(), channel()).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let resolved = executor
            .resolve(&TargetRef::Element { target })
            .expect("resolved target");
        let empty_hash = hex::encode(Sha256::digest(b""));
        let value = "updated";
        let value_hash = hex::encode(Sha256::digest(value.as_bytes()));
        executor.channel.lock().expect("channel").responses.extend([
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(json!({"object":{"objectId":"object-1"}})),
            Ok(probe(false, &empty_hash, 0)),
            Ok(viewport()),
            Ok(json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}})),
            Ok(live_ax(
                "textbox",
                "secret",
                true,
                json!({"name":"editable","value":{"value":"plaintext"}}),
            )),
            Ok(json!({"result":{"value":{"eligible":true}}})),
            Ok(probe(true, &value_hash, value.len())),
        ]);
        executor
            .dispatch(
                &Action::SetValue {
                    value: value.to_string(),
                },
                &resolved,
                &VerificationPolicy::SnapshotChanged,
                &CancellationToken::default(),
                i64::MAX,
            )
            .expect("set value");
        let channel = executor.channel.lock().expect("channel");
        assert!(
            !channel
                .methods
                .iter()
                .any(|method| method.starts_with("Input."))
        );
        assert!(!channel.methods.iter().any(|method| method == "DOM.focus"));
        let effect = channel
            .parameters
            .iter()
            .find(|parameters| {
                parameters
                    .get("functionDeclaration")
                    .and_then(Value::as_str)
                    == Some(SET_VALUE_EFFECT_FUNCTION)
            })
            .expect("target-bound effect");
        assert_eq!(
            effect.get("objectId").and_then(Value::as_str),
            Some("object-1")
        );
        assert_eq!(
            effect.pointer("/arguments/0/value").and_then(Value::as_str),
            Some(value)
        );
        assert!(SET_VALUE_EFFECT_FUNCTION.contains("new InputEvent(\"input\""));
        assert!(SET_VALUE_EFFECT_FUNCTION.contains("new Event(\"change\""));
    }

    #[test]
    fn engine_verifies_set_value_from_redacted_hash() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener");
        let port = listener.local_addr().expect("local address").port();
        let process_id = std::process::id();
        let process_generation =
            CdpConfig::process_generation(process_id).expect("process generation");
        let config = CdpConfig::localhost(port, "page-1", process_id, process_generation)
            .expect("configuration");
        let mut channel = editable_channel(false);
        channel.endpoint = config.endpoint();
        let executor = CdpExecutor::new(config, channel).expect("executor");
        let observation = executor
            .semantic_observation(&CancellationToken::default(), i64::MAX)
            .expect("observation");
        let target = observation.target("e0").expect("target");
        let empty_hash = hex::encode(Sha256::digest(b""));
        let value = "updated";
        let value_hash = hex::encode(Sha256::digest(value.as_bytes()));
        let frame = json!({"frameTree":{"frame":{"id":"frame-1","loaderId":"loader-1"}}});
        let object = json!({"object":{"objectId":"object-1"}});
        let mut channel = executor.channel.lock().expect("channel");
        channel.responses.extend([
            Ok(frame.clone()),
            Ok(object.clone()),
            Ok(probe(false, &empty_hash, 0)),
            Ok(viewport()),
            Ok(live_ax(
                "textbox",
                "secret",
                false,
                json!({"name":"editable","value":{"value":"plaintext"}}),
            )),
            Ok(frame.clone()),
            Ok(object.clone()),
            Ok(probe(false, &empty_hash, 0)),
            Ok(viewport()),
            Ok(frame.clone()),
            Ok(live_ax(
                "textbox",
                "secret",
                false,
                json!({"name":"editable","value":{"value":"plaintext"}}),
            )),
            Ok(json!({"result":{"value":{"eligible":true}}})),
            Ok(probe(true, &value_hash, value.len())),
            Ok(frame),
            Ok(object),
            Ok(probe(true, &value_hash, value.len())),
            Ok(viewport()),
            Ok(live_ax(
                "textbox",
                "secret",
                false,
                json!({"name":"editable","value":{"value":"plaintext"}}),
            )),
        ]);
        drop(channel);
        let request = ActionRequest {
            protocol_version: PROTOCOL_VERSION,
            action_version: PROTOCOL_VERSION,
            target_version: PROTOCOL_VERSION,
            verification_version: PROTOCOL_VERSION,
            operation_id: "cdp-set-value".to_string(),
            subject: "subject".to_string(),
            session_id: "session".to_string(),
            authority: SignedAuthority {
                grant: AuthorityGrant {
                    protocol_version: PROTOCOL_VERSION,
                    issuer: "host".to_string(),
                    key_id: "key".to_string(),
                    operation_id: "cdp-set-value".to_string(),
                    subject: "subject".to_string(),
                    session_id: "session".to_string(),
                    risk: SafetyClass::Reversible,
                    expires_at_ms: i64::MAX,
                    policy_generation: "generation".to_string(),
                    action_hash: "0".repeat(64),
                },
                signature: "0".repeat(128),
            },
            action: Action::SetValue {
                value: value.to_string(),
            },
            target: TargetRef::Element { target },
            interaction_mode: crate::InteractionMode::Interactive,
            deadline_at_ms: i64::MAX,
            verification: VerificationPolicy::TargetValueHash { sha256: value_hash },
            safety: SafetyClass::Reversible,
        };
        let directory = tempfile::tempdir().expect("temporary directory");
        let report = Engine::new(
            executor,
            directory.path().join("ledger.jsonl"),
            AllowAuthority,
        )
        .execute(&request, &CancellationToken::default())
        .expect("execution");
        assert!(matches!(
            report.acknowledgements.last().map(|ack| &ack.state),
            Some(AckState::Terminal { terminal })
                if matches!(terminal.as_ref(), Terminal::Succeeded { .. })
        ));
    }
}
