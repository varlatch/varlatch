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
/** The caller as its request authenticated it: GET /v1/me (capability identity.whoami). */
export type WhoAmI = components["schemas"]["WhoAmI"];
/** A tailnet listener request's device, or why there is none. */
export type TailnetDevice = components["schemas"]["TailnetDevice"];
export type CreatedIdentity = components["schemas"]["CreatedIdentity"];
export type Invitation = components["schemas"]["Invitation"];
export type MemberReview = components["schemas"]["MemberReview"];
export type MemberRemoval = components["schemas"]["MemberRemoval"];
export type OrganizationDeletion = components["schemas"]["OrganizationDeletion"];
/** An incident freeze of an Organization (capability organizations.incident-freeze, ADR-0055). */
export type IncidentFreeze = components["schemas"]["IncidentFreeze"];
/** A Sync Target that resumes pushing when the freeze is lifted. */
export type ResumingTarget = components["schemas"]["ResumingTarget"];
/** GET /v1/organizations/{org}/incident-freeze. */
export type IncidentFreezeState = operations["getIncidentFreeze"]["responses"]["200"]["content"]["application/json"];
/** POST /v1/organizations/{org}/incident-freeze/{freeze}/lift. */
export type IncidentFreezeLift = operations["liftIncidentFreeze"]["responses"]["200"]["content"]["application/json"];
export type ExposureReport = components["schemas"]["ExposureReport"];
export type MachineReach = components["schemas"]["MachineReach"];
export type ReachAction = components["schemas"]["ReachAction"];
export type ExposureConfirmation = components["schemas"]["ExposureConfirmation"];
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
export type TailnetEndpoint = components["schemas"]["TailnetEndpoint"];
export type CapabilitySummary = components["schemas"]["Capability"];
export type IssuedCapability = components["schemas"]["IssuedCapability"];
export type IssuedAgentCredential = components["schemas"]["IssuedAgentCredential"];
export type IssuedMachineCredential = components["schemas"]["IssuedMachineCredential"];
export type CapabilityExercise = components["schemas"]["CapabilityExercise"];
export type Webhook = components["schemas"]["Webhook"];
export type OwnCredential = components["schemas"]["OwnCredential"];
/** A person's passkey with its provenance (capability account.passkeys). */
export type OwnPasskey = components["schemas"]["OwnPasskey"];
export type PasskeyConfirmationOptions = components["schemas"]["PasskeyConfirmationOptions"];
/** Security Controls (capability security.controls, ADR-0054 Decisions 1 and 2). */
export type SecurityControlName = components["schemas"]["SecurityControlName"];
export type SecurityControlMode = components["schemas"]["SecurityControlMode"];
export type CredentialLifetimeConfig = components["schemas"]["CredentialLifetimeConfig"];
export type SecurityControl = components["schemas"]["SecurityControl"];
export type SecurityControlList = components["schemas"]["SecurityControlList"];
export type SecurityControlChangeInput = components["schemas"]["SecurityControlChangeInput"];
export type SecurityControlChange = components["schemas"]["SecurityControlChange"];
/** What the Security Controls in report mode counted (capability security.report, ADR-0054 Decision 9). */
export type SecurityControlReport = components["schemas"]["SecurityControlReport"];
export type SecurityControlCounts = components["schemas"]["SecurityControlCounts"];
export type SecurityReportEntry = components["schemas"]["SecurityReportEntry"];
export type SecurityReportReason = components["schemas"]["SecurityReportReason"];
/** A step-up approval (Approval Intent, ADR-0054 Decision 3). */
export type Approval = components["schemas"]["Approval"];
export type ApprovalChange = components["schemas"]["ApprovalChange"];
export type ApprovalOptions = components["schemas"]["ApprovalOptions"];
/** The request header that carries an approved step-up approval's id. */
export const APPROVAL_HEADER = "Varlatch-Approval";
/** The Security Controls, in the order they are shown. */
export const SECURITY_CONTROLS = ["requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"] as const;
export type IssuedCliCredential = components["schemas"]["IssuedCliCredential"];
export type OidcBinding = components["schemas"]["OidcBinding"];
export type IssuedOidcCredential = components["schemas"]["IssuedOidcCredential"];
export type DeviceSignInStarted = components["schemas"]["DeviceSignInStarted"];
export type DeviceSignInLookup = components["schemas"]["DeviceSignInLookup"];
export type CreatedWebhook = components["schemas"]["CreatedWebhook"];
export type SyncPlatform = components["schemas"]["SyncPlatform"];
export type PlatformConnection = components["schemas"]["PlatformConnection"];
export type GitHubAccount = components["schemas"]["GitHubAccount"];
export type GitHubApp = components["schemas"]["GitHubApp"];
export type GitHubAppRegistrationStart = components["schemas"]["GitHubAppRegistrationStart"];
export type GitHubAppRegistrationRegistered = components["schemas"]["GitHubAppRegistrationRegistered"];
export type GitHubAppRegistrationRefused = components["schemas"]["GitHubAppRegistrationRefused"];
export type GitHubAppRegistrationFailed = components["schemas"]["GitHubAppRegistrationFailed"];
export type GitHubAppImportFailed = components["schemas"]["GitHubAppImportFailed"];
export type GitHubAppInstallation = components["schemas"]["GitHubAppInstallation"];
export type GitHubAppInstallationListing = components["schemas"]["GitHubAppInstallationListing"];
export type AccessCheck = components["schemas"]["AccessCheck"];
export type DestinationOption = components["schemas"]["DestinationOption"];
export type DestinationListing = components["schemas"]["DestinationListing"];
export type SyncTarget = components["schemas"]["SyncTarget"];
export type SyncTargetNote = components["schemas"]["SyncTargetNote"];
export type SyncMapping = components["schemas"]["SyncMapping"];
export type SyncMappingInput = components["schemas"]["SyncMappingInput"];
export type SyncLedgerName = components["schemas"]["SyncLedgerName"];

export type InstallationBackups = components["schemas"]["InstallationBackups"];
export type InstallationRelease = components["schemas"]["InstallationRelease"];
export type ReleaseCheckFailure = components["schemas"]["ReleaseCheckFailure"];
export type InstallationListeners = components["schemas"]["InstallationListeners"];
export type TailnetListenerReport = components["schemas"]["TailnetListenerReport"];
export type ObservedCheck = components["schemas"]["ObservedCheck"];
export type ObservedNode = components["schemas"]["ObservedNode"];
/** Machine credentials never used, idle, or without expiry (capability security.credential-review). */
export type CredentialReview = components["schemas"]["CredentialReview"];
export type ReviewedCredential = components["schemas"]["ReviewedCredential"];
/** Service credentials expiring within 7 days or expired (part of the credential review). */
export type CredentialExpiryReview = components["schemas"]["CredentialExpiryReview"];
export type ExpiringCredential = components["schemas"]["ExpiringCredential"];
/** The approval keys of an Organization's admins (capability security.approval-keys, ADR-0054 Decision 4). */
export type ApprovalKeys = components["schemas"]["ApprovalKeys"];
export type AdminApprovalKeys = components["schemas"]["AdminApprovalKeys"];
export type ApprovalKey = components["schemas"]["ApprovalKey"];
/** The caller's own organization-level permissions (capability organizations.permissions). */
export type OrganizationPermissions = components["schemas"]["OrganizationPermissions"];
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
