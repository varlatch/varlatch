// SPDX-License-Identifier: Apache-2.0
export * from "./errors.js";
export type { paths, components, operations } from "./generated/api.js";

import type { components, operations } from "./generated/api.js";

/** Convenience aliases over the generated OpenAPI component schemas. */
export type Organization = components["schemas"]["Organization"];
export type Project = components["schemas"]["Project"];
export type Environment = components["schemas"]["Environment"];
export type Tier = components["schemas"]["Tier"];
export type EnvironmentKind = components["schemas"]["EnvironmentKind"];
export type ContractAuthority = components["schemas"]["ContractAuthority"];
export type ValueVersion = components["schemas"]["ValueVersion"];
export type ValueRotation = components["schemas"]["ValueRotation"];
export type EffectiveConfiguration = components["schemas"]["EffectiveConfiguration"];
export type EffectiveConfigurationItem =
  components["schemas"]["EffectiveConfigurationItem"];
export type ValidationReport = components["schemas"]["ValidationReport"];
export type StateManifest = components["schemas"]["StateManifest"];
export type CallerView = components["schemas"]["CallerView"];
export type StrictRetrieval = components["schemas"]["StrictRetrieval"];
export type DisclosurePurpose = components["schemas"]["DisclosurePurpose"];
export type ContractRevision = components["schemas"]["ContractRevision"];
export type Identity = components["schemas"]["Identity"];
export type Profile = components["schemas"]["Profile"];
export type CreatedIdentity = components["schemas"]["CreatedIdentity"];
export type Invitation = components["schemas"]["Invitation"];
export type InvitationStatus = components["schemas"]["InvitationStatus"];
export type Action = components["schemas"]["Action"];
export type GrantScope = components["schemas"]["GrantScope"];
export type Grant = components["schemas"]["Grant"];
export type GrantReplacement = components["schemas"]["GrantReplacement"];
export type Role = components["schemas"]["Role"];
export type Group = components["schemas"]["Group"];
export type Requirement = components["schemas"]["Requirement"];
export type RequirementTarget = components["schemas"]["RequirementTarget"];
export type TailnetSelector = components["schemas"]["TailnetSelector"];
export type ConfigItemSearchResult = components["schemas"]["ConfigItemSearchResult"];
export type AuditEvent = components["schemas"]["AuditEvent"];
/** One entry of the audit listing's credentials sidecar (capability audit.attribution). */
export type AuditCredential = components["schemas"]["AuditCredential"];
/** Server-side audit filters (capability audit.filters): the listing's and export's optional query parameters. */
export type AuditEventFilters = Omit<
  NonNullable<operations["listAuditEvents"]["parameters"]["query"]>,
  "limit" | "cursor"
>;
export type Meta = components["schemas"]["Meta"];
export type CapabilitySummary = components["schemas"]["Capability"];
export type IssuedCapability = components["schemas"]["IssuedCapability"];
export type IssuedAgentCredential = components["schemas"]["IssuedAgentCredential"];
export type IssuedMachineCredential = components["schemas"]["IssuedMachineCredential"];
export type CapabilityExercise = components["schemas"]["CapabilityExercise"];
export type Webhook = components["schemas"]["Webhook"];
export type OwnCredential = components["schemas"]["OwnCredential"];
export type IssuedCliCredential = components["schemas"]["IssuedCliCredential"];
export type OidcBinding = components["schemas"]["OidcBinding"];
export type IssuedOidcCredential = components["schemas"]["IssuedOidcCredential"];
export type DeviceSignInStarted = components["schemas"]["DeviceSignInStarted"];
export type DeviceSignInLookup = components["schemas"]["DeviceSignInLookup"];
export type CreatedWebhook = components["schemas"]["CreatedWebhook"];
export type SyncPlatform = components["schemas"]["SyncPlatform"];
export type PlatformConnection = components["schemas"]["PlatformConnection"];
export type AccessCheck = components["schemas"]["AccessCheck"];
export type DestinationOption = components["schemas"]["DestinationOption"];
export type DestinationListing = components["schemas"]["DestinationListing"];
export type SyncTarget = components["schemas"]["SyncTarget"];
export type SyncMapping = components["schemas"]["SyncMapping"];
export type SyncMappingInput = components["schemas"]["SyncMappingInput"];
export type SyncLedgerName = components["schemas"]["SyncLedgerName"];

export type InstallationBackups = components["schemas"]["InstallationBackups"];
export {
  MAX_TARGETS_PER_ITEM,
  TRANSPORT_OWNED_HEADERS,
  TargetError,
  canonicalTargets,
  describeTargets,
  formatTarget,
  isTransportOwnedHeader,
  jsonPointerTokens,
  parseTarget,
  type Target,
  type TargetKind,
} from "./targets.js";
