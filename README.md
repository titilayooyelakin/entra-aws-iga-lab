# Identity Governance & Administration (IGA) Lab: OmniCorp Access Review Remediation

A hands-on IGA project covering the Joiner-Mover-Leaver (JML) lifecycle, an access certification campaign, and a working Microsoft Entra ID to AWS IAM Identity Center federation with automated provisioning and a leaver kill-switch.

**Architecture (design):** Workday → Microsoft Entra ID → SAML + SCIM → AWS IAM Identity Center → permission sets → AWS account

**What I built in the lab:** Entra ID (identity source) → SAML sign-in + SCIM provisioning → AWS IAM Identity Center → `ReadOnlyAccess` permission set → AWS account. Workday is part of the design only and was not integrated; the test user was created by hand in Entra.

> **Why AWS IAM Identity Center?** It was selected as the federation target because it supports SCIM-based automated provisioning and deprovisioning, which lifecycle automation requires. Plain IAM SAML federation has no SCIM, so users and groups would have to be created in AWS by hand.

---

## Contents

1. [Scenario](#scenario)
2. [Part 1: Automated JML lifecycle blueprint](#part-1-automated-jml-lifecycle-blueprint)
3. [Part 2: Access certification decisions](#part-2-access-certification-decisions)
4. [Part 3: Lab implementation](#part-3-lab-implementation)
5. [Issues encountered and fixes](#issues-encountered-and-fixes)
6. [Findings and limitations](#findings-and-limitations)
7. [Cleanup](#cleanup)

---

## Scenario

OmniCorp has 500 employees and manages access to GitHub, Salesforce, Jira and Workday through an enterprise identity provider. It failed a SOC 2 review with three findings:

1. **Dormant accounts:** 45 contractor accounts with no login for over 120 days still had active access.
2. **Permission accumulation (the "mover" flaw):** employees moving from Marketing to Engineering kept their old Marketing database privileges.
3. **Orphaned admin accounts:** two former sysadmins who left six months earlier still had active global admin accounts, because offboarding was done by verbal request.

The goal was to design an automated JML workflow, run an access certification review, and demonstrate group/entitlement-based access and an instant offboarding kill-switch.

---

## Part 1: Automated JML lifecycle blueprint

**Design principle:** Workday is the single source of truth for identity state. Entra ID is the enforcement point. All access flows through groups and access packages, never direct assignments.

### 1. Joiner (onboarding)

| Element | Detail |
|---|---|
| **Trigger source** | Workday "Hire" business process completes. Contractor records carry a mandatory end date and sponsor. |
| **System of record** | Workday (department, title, manager, worker type, hire/end date) |

**Actions taken:**
1. Workday-to-Entra inbound provisioning creates the account from HR attributes. No ticket is needed.
2. A Lifecycle Workflow runs before the start date and issues a Temporary Access Pass to the manager or personal address.
3. **Dynamic groups** (for example `department -eq "Marketing"`) place the user in the right groups. Those groups are assigned to apps (GitHub, Jira, Salesforce) and pushed with SCIM.
4. A **Conditional Access** policy requires MFA registration and MFA at sign-in, with phishing-resistant MFA for admins.
5. Contractors get an `employeeLeaveDateTime` and a sponsor at creation, so expiry is built in.

### 2. Mover (internal transfer)

| Element | Detail |
|---|---|
| **Trigger source** | Workday "Change Job/Transfer" event updates `department`, `jobTitle` or `manager`. |
| **System of record** | Workday |

**Actions taken:**
1. The attribute sync updates the user in the IdP.
2. **Dynamic group rules re-evaluate.** The user leaves `Marketing-All` and joins `Engineering-All`. Because app access is tied to groups, the old entitlements are removed and the new ones granted. This is what prevents permission creep.
3. A mover Lifecycle Workflow removes non-birthright access packages and triggers a manager re-certification.
4. **Non-birthright access** (such as database admin) goes through time-bound access packages with approval, or just-in-time elevation through PIM. It is never standing and never directly assigned.
5. A quarterly access review flags **direct** assignments, since those bypass the automation.

### 3. Leaver (offboarding)

| Element | Detail |
|---|---|
| **Trigger source** | Workday "Termination" event, or the contract end date reaching `employeeLeaveDateTime`. HR or security can trigger an emergency termination. |
| **System of record** | Workday |

**Actions taken (Lifecycle Workflow, at the scheduled time):**
1. Disable the account (`accountEnabled = false`).
2. **Revoke all sessions and refresh tokens** (`revokeSignInSessions`).
3. Remove the user from all groups and access packages.
4. Remove admin and PIM role assignments, and reset or delete MFA methods.
5. SCIM deprovisioning disables the account in connected apps. For apps without SCIM, open a ticket for the app owner with an SLA.
6. Remove licenses and convert or forward the mailbox.
7. Notify the manager and security, and write everything to the audit log.
8. Delete the account after the retention period.

**Backstop controls:** Continuous Access Evaluation (CAE) for near-real-time token invalidation, plus a weekly report of enabled accounts with no matching active Workday record, which catches orphans.

> **Licensing note:** Lifecycle Workflows, Access Reviews and PIM need Entra ID Governance, P2 or equivalent licensing. They were not available in the Free tenant used for the lab, so this section is a design. Part 3 demonstrates the Entra-to-AWS portion of the flow.

---

## Part 2: Access certification decisions

| User | Violation / risk | Action | Justification |
|---|---|---|---|
| **j.doe@omnicorp.com** (Marketing Manager, active 2 days ago) | `Prod-Database-Admin` is far outside a marketing role. This is a least-privilege violation and standing privileged access in production. | **Modify** | Remove `Prod-Database-Admin`. Keep `Marketing-All` and `Jira-Users`. If there is a documented need, re-grant as time-bound access through PIM with approval. Review how it was granted. |
| **c.smith@contractor.io** (External developer, 145 days inactive) | Dormant account over the 120-day threshold with active code (GitHub) and cloud (AWS) access. External identities with no activity are a prime takeover target. | **Revoke** | Disable the account and remove `GitHub-Core` and `AWS-Dev-Access`. Confirm with the sponsor. If the engagement is ongoing, issue a new request with an end date instead of recertifying the old access. |
| **a.jones@omnicorp.com** (Terminated sysadmin, 180 days) | Orphaned **Global Tenant Admin** and Domain Controller access for someone who left six months ago. This is the most critical finding and a complete offboarding failure. | **Revoke (immediately, treat as an incident)** | Disable, revoke sessions and strip all admin roles. Review sign-in and audit logs since the departure date. Rotate shared secrets, service-account credentials and break-glass accounts they knew. Document the root cause: manual, verbal offboarding. |
| **m.chen@omnicorp.com** (Sales → Finance, today) | Classic mover flaw. `Sales-CRM-Full` was kept alongside `Finance-Billing-System`. This is permission accumulation and a possible segregation-of-duties conflict. | **Modify** | Remove `Sales-CRM-Full`. Keep `Finance-Billing-System` after the new manager confirms it. Allow a short, documented read-only transition window if needed. |

**Result:** two revokes, two modifies, no certifies. None of the four profiles justified keeping access as it was.

---

## Part 3: Lab implementation

**Environment:** Microsoft Entra ID (Free tenant) and AWS IAM Identity Center (organization instance, Europe (Ireland)).

### Step 1: Create the lifecycle group and the test contractor (Joiner)

I created the security group `SG-Temporary-Contractors` (Assigned membership) and the test user `contractor.test`, and added the user to the group.

![Group created](screenshots/27-group-created.png)
*The `SG-Temporary-Contractors` security group in Entra ID.*

![Users list](screenshots/29-users-list.png)
*The tenant's users, including `Test Contractor`.*

![Group members](screenshots/28-group-members.png)
*`Test Contractor` is a member of `SG-Temporary-Contractors`.*

### Step 2: Enable AWS IAM Identity Center and switch the identity source

I enabled IAM Identity Center with a single-region organization instance, then changed the identity source from the built-in directory to an external identity provider.

![Identity Center enabled](screenshots/01-identity-center-enabled.png)
*IAM Identity Center created. The identity source is still the default directory.*

![Choose identity source](screenshots/02-choose-identity-source.png)
*"External identity provider" selected.*

![Service provider metadata](screenshots/03-service-provider-metadata.png)
*AWS service provider metadata, downloaded to give to Entra.*

### Step 3: Configure SAML single sign-on in Entra

I added the **AWS IAM Identity Center** enterprise application, uploaded the AWS metadata file, and used the resulting federation metadata to finish the trust in AWS.

![Entra enterprise app](screenshots/30-enterprise-apps.png)
*The AWS IAM Identity Center enterprise application in Entra.*

![Entra app overview](screenshots/04-entra-aws-app-overview.png)
*App overview with the getting-started tasks.*

![SAML metadata upload](screenshots/05-entra-saml-metadata-upload.png)
*AWS metadata uploaded. The SAML configuration saved successfully.*

![SAML configuration](screenshots/07-entra-saml-config.png)
*Basic SAML configuration and claims. The unique user identifier is the user principal name.*

![Identity source changed](screenshots/06-identity-source-changed.png)
*AWS confirms the identity source changed to an external identity provider.*

### Step 4: Enable SCIM provisioning

I enabled automatic provisioning in AWS, created an access token, and entered the SCIM endpoint and token in Entra. The connection test passed on the second attempt (see [Issues](#issues-encountered-and-fixes)).

![SCIM test connection](screenshots/08-scim-test-connection.png)
*Provisioning test connection succeeded. The tenant URL is hidden and the token is masked.*

![Provisioning overview](screenshots/09-provisioning-overview.png)
*Provisioning configuration created, ready to start.*

### Step 5: Assign access and provision the user

I assigned the user to the AWS application. **Group assignment was not available**, because it needs a higher Entra plan, so the user was assigned directly. After provisioning, the user appeared in AWS, created by SCIM.

![User assigned to the app](screenshots/10-user-assigned-to-app.png)
*"1 user & 0 groups have been assigned access."*

![User provisioned in AWS](screenshots/11-user-provisioned-in-aws.png)
*`Test Contractor` exists in IAM Identity Center, status Enabled, created by SCIM.*

### Step 6: Grant entitlements with a permission set

I created the `ReadOnlyAccess` permission set and assigned it to the user for the AWS account.

![Permission set](screenshots/12-permission-set-created.png)
*`ReadOnlyAccess` permission set created.*

![Account assignment](screenshots/13-account-assignment.png)
*Permission set assigned to the user on the AWS account.*

### Step 7: Test the login

I signed in as `contractor.test` in a private browser window through the AWS access portal. Entra forced a password change and Microsoft prompted for security info registration; I registered Microsoft Authenticator. Entra then authenticated the user and AWS granted access.

![MFA registration](screenshots/14-mfa-registration.png)
*Microsoft Authenticator registered during the first sign-in.*

![Access portal](screenshots/15-access-portal.png)
*The AWS access portal shows the assigned account.*

![Console home](screenshots/16-console-home.png)
*The AWS console opened with the `ReadOnlyAccess` role.*

### Step 8: Run the kill-switch (Leaver)

I revoked the user's sessions, then disabled the account, then ran provisioning on demand.

![Revoke sessions](screenshots/17-revoke-sessions.png)
*Sign-in sessions revoked for the user.*

![User updated](screenshots/18-user-updated.png)
*Account properties updated (account disabled).*

![Provision on demand](screenshots/19-provision-on-demand.png)
*Provision on demand: the user was imported, and the scope step was skipped.*

![Skip reason](screenshots/20-provision-skip-reason.png)
*The skip reason is `RedundantSoftDelete`. The disable had already been processed and pushed to AWS (`IsActive: False`).*

![AWS user disabled](screenshots/21-aws-user-disabled.png)
*In AWS the user's status is **Disabled**.*

![Failed sign-in](screenshots/22-failed-signin-page.png)
*The disabled user cannot sign in.*

### Step 9: Verify with logs

![Sign-in logs](screenshots/23-signin-logs.png)
*Sign-in log: the first sign-ins were interrupted by the forced password change (50055) and the stay-signed-in prompt (50140). The 4:39 sign-in succeeded. The 5:29 attempt after the disable failed with 50126.*

![Revoke audit](screenshots/24-audit-revoke-activity.png)
*Audit log: "Update StsRefreshTokenValidFrom Timestamp" at 5:07.*

![Revoke audit properties](screenshots/25-audit-revoke-properties.png)
*`StsRefreshTokensValidFrom` moved from 03:35:22Z to 04:07:56Z, which invalidates earlier tokens.*

![Disable account audit](screenshots/26-audit-disable-account.png)
*Audit log: "Disable account" at 5:10, tied to the admin who made the change.*

### Timeline

Times are local (Lagos, UTC+1). The property panel shows UTC, so 5:07 AM local is 04:07Z.

| Time | Event |
|---|---|
| 4:35 | Temporary password changed at first sign-in |
| 4:37-4:39 | Security info (Authenticator) registered |
| 4:39 | Successful sign-in to the AWS access portal |
| 5:07 | Sessions revoked |
| 5:10 | Account disabled |
| 5:29 | Sign-in attempt failed (50126) |
| Later | AWS shows the user as Disabled |

---

## Issues encountered and fixes

| Problem | Cause | Fix |
|---|---|---|
| SCIM test connection failed with **401 Unauthorized** (`CredentialValidationUnavailable`) | The secret token was wrong or was never saved when AWS showed it. AWS displays an access token only once, and the token ID is not the token. | Generated a new token in AWS, pasted it into the Secret Token field and re-ran the test. Then deleted the unused old token. |
| Provisioning the user failed with **"name: The attribute name is required"** | AWS requires a first and last name, and the test user only had a display name. | Added first and last name in Entra and provisioned again. |
| Group could not be assigned to the AWS app: "Groups are not available for assignment due to your Active Directory plan level" | Group-based app assignment needs a paid Entra plan. | Assigned the user directly and documented the limitation (below). |
| Provision on demand showed **Skipped** after the disable | The deactivation had already been synced (`RedundantSoftDelete`). | Confirmed the result in AWS, where the user shows Disabled. |

---

## Findings and limitations

- **Groups beat direct assignments.** The group-based design is the right production model, because access follows membership and removing someone from a group removes access. In this lab the group exists and contains the user, but it was not assigned to the app, so it did not drive any access.
- **SCIM needs complete source data.** The "name required" error shows that a missing HR attribute breaks downstream provisioning. In the real design Workday supplies first and last name.
- **Disabling is not the whole kill-switch.** Blocking sign-in stops new sign-ins, but an already-issued access token or an open console session can stay valid until it expires unless the app supports Continuous Access Evaluation. I did not measure how long the open session lasted. Revoking sessions, disabling the account and verifying the downstream state in AWS are all needed.
- **Failed sign-in showed error 50126**, a generic "invalid username or password" code. Entra uses vague messages so attackers cannot learn whether an account exists or is disabled. The log did not record an account-disabled code for my attempt, so the real proof that the kill-switch worked is the AWS **Disabled** status and the provisioning result, supported by the audit log.
- **Sync is not instant.** Entra's automatic cycle runs about every 40 minutes, so I used provision on demand for the demonstration.
- **Not implemented in the lab:** Workday integration, dynamic groups, Lifecycle Workflows, Conditional Access policies, Access Reviews and PIM. These need licensing the Free tenant does not include, and they are covered only in the Part 1 design.

---

## Cleanup

To avoid leaving stray resources, after collecting the evidence I will:

- [ ] Delete the test user `contractor.test` and the group `SG-Temporary-Contractors` in Entra
- [ ] Remove the AWS IAM Identity Center enterprise application from Entra
- [ ] Remove the account assignment and the `ReadOnlyAccess` permission set in AWS
- [ ] Delete the SCIM access token in AWS
- [ ] Disable IAM Identity Center in AWS

---

## Skills demonstrated

Identity governance (JML, least privilege, access certification, segregation of duties) · Microsoft Entra ID · SAML 2.0 federation · SCIM provisioning · AWS IAM Identity Center · audit-log analysis · troubleshooting · security-conscious documentation
