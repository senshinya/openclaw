import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { removeStaleOAuthProfiles } from "./profiles.js";
import { ensureAuthProfileStore, saveAuthProfileStore } from "./store.js";
import type { OAuthCredential } from "./types.js";

function makeTmpAgentDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-stale-oauth-"));
}

function makeOAuth(provider: string, email?: string): OAuthCredential {
  return {
    type: "oauth",
    provider,
    access: "access-token",
    refresh: "refresh-token",
    expires: Date.now() + 60_000,
    ...(email ? { email } : {}),
  };
}

describe("removeStaleOAuthProfiles", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs) {
      fs.rmSync(d, { recursive: true, force: true });
    }
    dirs.length = 0;
  });

  it("removes stale :default OAuth profile when a named profile replaces it", async () => {
    const agentDir = makeTmpAgentDir();
    dirs.push(agentDir);

    // Seed store with stale default + fresh named profile.
    const store = ensureAuthProfileStore(agentDir);
    store.profiles["openai-codex:default"] = makeOAuth("openai-codex");
    store.profiles["openai-codex:user@example.com"] = makeOAuth("openai-codex", "user@example.com");
    store.usageStats = {
      "openai-codex:default": { lastUsed: Date.now() - 100_000 },
    };
    saveAuthProfileStore(store, agentDir);

    await removeStaleOAuthProfiles({
      provider: "openai-codex",
      keepProfileIds: new Set(["openai-codex:user@example.com"]),
      agentDir,
    });

    const updated = ensureAuthProfileStore(agentDir);
    expect(updated.profiles["openai-codex:default"]).toBeUndefined();
    expect(updated.profiles["openai-codex:user@example.com"]).toBeDefined();
    expect(updated.usageStats?.["openai-codex:default"]).toBeUndefined();
  });

  it("does not remove non-OAuth (api_key / token) profiles", async () => {
    const agentDir = makeTmpAgentDir();
    dirs.push(agentDir);

    const store = ensureAuthProfileStore(agentDir);
    store.profiles["provider:api-profile"] = {
      type: "api_key",
      provider: "provider",
      key: "sk-test",
    };
    store.profiles["provider:new-oauth"] = makeOAuth("provider", "new@test.com");
    saveAuthProfileStore(store, agentDir);

    await removeStaleOAuthProfiles({
      provider: "provider",
      keepProfileIds: new Set(["provider:new-oauth"]),
      agentDir,
    });

    const updated = ensureAuthProfileStore(agentDir);
    expect(updated.profiles["provider:api-profile"]).toBeDefined();
    expect(updated.profiles["provider:new-oauth"]).toBeDefined();
  });

  it("cleans up order and lastGood references to removed profiles", async () => {
    const agentDir = makeTmpAgentDir();
    dirs.push(agentDir);

    const store = ensureAuthProfileStore(agentDir);
    store.profiles["p:default"] = makeOAuth("p");
    store.profiles["p:user@test.com"] = makeOAuth("p", "user@test.com");
    store.order = { p: ["p:default", "p:user@test.com"] };
    store.lastGood = { p: "p:default" };
    saveAuthProfileStore(store, agentDir);

    await removeStaleOAuthProfiles({
      provider: "p",
      keepProfileIds: new Set(["p:user@test.com"]),
      agentDir,
    });

    const updated = ensureAuthProfileStore(agentDir);
    expect(updated.profiles["p:default"]).toBeUndefined();
    expect(updated.order?.p).toEqual(["p:user@test.com"]);
    expect(updated.lastGood?.p).toBeUndefined();
  });

  it("is a no-op when there are no stale profiles", async () => {
    const agentDir = makeTmpAgentDir();
    dirs.push(agentDir);

    const store = ensureAuthProfileStore(agentDir);
    store.profiles["p:user@test.com"] = makeOAuth("p", "user@test.com");
    saveAuthProfileStore(store, agentDir);

    await removeStaleOAuthProfiles({
      provider: "p",
      keepProfileIds: new Set(["p:user@test.com"]),
      agentDir,
    });

    const updated = ensureAuthProfileStore(agentDir);
    expect(updated.profiles["p:user@test.com"]).toBeDefined();
  });
});
