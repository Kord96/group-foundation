/** Independently generated MLS signing key fingerprint in canonical base64url. */
export interface MemberIdentity { readonly signingKeyFingerprint: string; }
/** Authenticated group scope and the consumer's opaque predecessor cursor. */
export interface GroupContext { readonly groupId: string; readonly profile: string; readonly predecessor: string; }
export const GROUP_MEMBER_ID_DOMAIN = "group-foundation.group.member-id.v1\0" as const;
export const GROUP_SIDECAR_PREFIX = "group-foundation.sidecar." as const;
export class GroupError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.name = "GroupError"; this.code = code; }
}
export * from "./native-state.js";
