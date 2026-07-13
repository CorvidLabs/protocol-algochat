interface Implementation {
    id: string;
    name?: string;
    repo?: string;
}

interface ImplementationRegistry {
    implementations: Implementation[];
}

const requiredDocuments = [
    "README.md",
    "PROTOCOL.md",
    "IMPLEMENTATION.md",
    "SECURITY.md",
    "TEST-VECTORS.md",
] as const;

for (const document of requiredDocuments) {
    const file = Bun.file(document);
    if (!(await file.exists()) || file.size === 0) {
        throw new Error(`Missing or empty required document: ${document}`);
    }
}

const registryValue: unknown = await Bun.file("implementations.json").json();
if (
    typeof registryValue !== "object" ||
    registryValue === null ||
    !("implementations" in registryValue) ||
    !Array.isArray((registryValue as ImplementationRegistry).implementations)
) {
    throw new Error("implementations.json must contain an implementations array");
}

const implementations = (registryValue as ImplementationRegistry).implementations;
const identifiers = new Set<string>();
for (const implementation of implementations) {
    if (typeof implementation.id !== "string" || implementation.id.length === 0) {
        throw new Error("Every implementation must have a non-empty id");
    }
    if (identifiers.has(implementation.id)) {
        throw new Error(`Duplicate implementation id: ${implementation.id}`);
    }
    identifiers.add(implementation.id);
}

console.log(`Validated ${requiredDocuments.length} protocol documents and ${implementations.length} implementations.`);
