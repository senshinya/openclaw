import { normalizeStringEntries } from "../../shared/string-normalization.js";
import { normalizeSecretInput } from "../../utils/normalize-secret-input.js";
import { normalizeProviderId, normalizeProviderIdForAuth } from "../provider-id.js";
import {
  ensureAuthProfileStore,
  saveAuthProfileStore,
  updateAuthProfileStoreWithLock,
} from "./store.js";
import type { AuthProfileCredential, AuthProfileStore } from "./types.js";

export function dedupeProfileIds(profileIds: string[]): string[] {
  return [...new Set(profileIds)];
}

export async function setAuthProfileOrder(params: {
  agentDir?: string;
  provider: string;
  order?: string[] | null;
}): Promise<AuthProfileStore | null> {
  const providerKey = normalizeProviderId(params.provider);
  const sanitized =
    params.order && Array.isArray(params.order) ? normalizeStringEntries(params.order) : [];
  const deduped = dedupeProfileIds(sanitized);

  return await updateAuthProfileStoreWithLock({
    agentDir: params.agentDir,
    updater: (store) => {
      store.order = store.order ?? {};
      if (deduped.length === 0) {
        if (!store.order[providerKey]) {
          return false;
        }
        delete store.order[providerKey];
        if (Object.keys(store.order).length === 0) {
          store.order = undefined;
        }
        return true;
      }
      store.order[providerKey] = deduped;
      return true;
    },
  });
}

export function upsertAuthProfile(params: {
  profileId: string;
  credential: AuthProfileCredential;
  agentDir?: string;
}): void {
  const credential =
    params.credential.type === "api_key"
      ? {
          ...params.credential,
          ...(typeof params.credential.key === "string"
            ? { key: normalizeSecretInput(params.credential.key) }
            : {}),
        }
      : params.credential.type === "token"
        ? { ...params.credential, token: normalizeSecretInput(params.credential.token) }
        : params.credential;
  const store = ensureAuthProfileStore(params.agentDir);
  store.profiles[params.profileId] = credential;
  saveAuthProfileStore(store, params.agentDir);
}

export async function upsertAuthProfileWithLock(params: {
  profileId: string;
  credential: AuthProfileCredential;
  agentDir?: string;
}): Promise<AuthProfileStore | null> {
  return await updateAuthProfileStoreWithLock({
    agentDir: params.agentDir,
    updater: (store) => {
      store.profiles[params.profileId] = params.credential;
      return true;
    },
  });
}

export function listProfilesForProvider(store: AuthProfileStore, provider: string): string[] {
  const providerKey = normalizeProviderIdForAuth(provider);
  return Object.entries(store.profiles)
    .filter(([, cred]) => normalizeProviderIdForAuth(cred.provider) === providerKey)
    .map(([id]) => id);
}

/**
 * Remove OAuth profiles for a provider that were NOT part of the latest auth
 * result.  This prevents stale `:default` profiles from lingering after a
 * re-authentication that returns a named profile (e.g. `provider:email`).
 *
 * Only OAuth profiles are pruned — API-key and token profiles are left alone
 * because they are managed explicitly by the user.
 */
export async function removeStaleOAuthProfiles(params: {
  provider: string;
  keepProfileIds: Set<string>;
  agentDir?: string;
}): Promise<void> {
  const providerKey = normalizeProviderIdForAuth(params.provider);
  await updateAuthProfileStoreWithLock({
    agentDir: params.agentDir,
    updater: (store) => {
      const stale = Object.entries(store.profiles).filter(
        ([id, cred]) =>
          normalizeProviderIdForAuth(cred.provider) === providerKey &&
          cred.type === "oauth" &&
          !params.keepProfileIds.has(id),
      );
      if (stale.length === 0) {
        return false;
      }
      for (const [id] of stale) {
        delete store.profiles[id];
        if (store.usageStats?.[id]) {
          delete store.usageStats[id];
        }
      }
      // Clean up order lists.
      if (store.order) {
        for (const [provider, list] of Object.entries(store.order)) {
          const filtered = list.filter((id) => !stale.some(([s]) => s === id));
          if (filtered.length !== list.length) {
            if (filtered.length > 0) {
              store.order[provider] = filtered;
            } else {
              delete store.order[provider];
            }
          }
        }
      }
      // Clean up lastGood.
      if (store.lastGood) {
        for (const [provider, profileId] of Object.entries(store.lastGood)) {
          if (stale.some(([id]) => id === profileId)) {
            delete store.lastGood[provider];
          }
        }
      }
      return true;
    },
  });
}

export async function markAuthProfileGood(params: {
  store: AuthProfileStore;
  provider: string;
  profileId: string;
  agentDir?: string;
}): Promise<void> {
  const { store, provider, profileId, agentDir } = params;
  const updated = await updateAuthProfileStoreWithLock({
    agentDir,
    updater: (freshStore) => {
      const profile = freshStore.profiles[profileId];
      if (!profile || profile.provider !== provider) {
        return false;
      }
      freshStore.lastGood = { ...freshStore.lastGood, [provider]: profileId };
      return true;
    },
  });
  if (updated) {
    store.lastGood = updated.lastGood;
    return;
  }
  const profile = store.profiles[profileId];
  if (!profile || profile.provider !== provider) {
    return;
  }
  store.lastGood = { ...store.lastGood, [provider]: profileId };
  saveAuthProfileStore(store, agentDir);
}
