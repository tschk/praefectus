const manifest = await Bun.file(
  new URL("./package.json", import.meta.url),
).json();
const allowed = new Set([
  "0BSD",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "Unlicense",
]);
const inventory: string[] = [];

for (const [name, version] of Object.entries<string>(
  manifest.dependencies ?? {},
)) {
  const dependency = await Bun.file(
    new URL(`./node_modules/${name}/package.json`, import.meta.url),
  ).json();
  if (dependency.name !== name || dependency.version !== version)
    throw new Error(`locked production dependency mismatch: ${name}`);
  if (!allowed.has(dependency.license))
    throw new Error(`unapproved production dependency license: ${name}`);
  if (
    Object.keys(dependency.dependencies ?? {}).length ||
    Object.keys(dependency.optionalDependencies ?? {}).length
  )
    throw new Error(`production dependency inventory is incomplete: ${name}`);
  inventory.push(
    `${dependency.name}@${dependency.version} ${dependency.license}`,
  );
}

console.log(inventory.sort().join("\n"));
