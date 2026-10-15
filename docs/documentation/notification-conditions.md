# Notification conditions

## Scan notification conditions {#notification-conditions}

Scan notifications are sent according to the notification mode and the findings and changes in the current cycle.
See [Configuration](configuration.md) for notification modes and destinations.

### Delivery in diff mode {#diff-delivery}

`diff` mode reports changes since the previous scan and the current unresolved state.
In the following table, “findings” includes ordinary packages, EOL packages, and EOL base operating systems.

| State | Scan notification |
| --- | --- |
| Changes detected | Reports changes such as new and resolved findings |
| No changes | Reports that nothing changed and shows the current unresolved state if findings remain |
| No findings | If there are also no changes, sends only when notifications without findings are enabled |
| Last finding resolved | Reports the resolution even when no current findings remain |
| Scan failure | Sends even without findings or changes |
| Findings retained | Sends even without changes if previous package findings are retained because Kubernetes identities are unconfirmed |
| Image content changed or reference updated | Sends even without package changes |

The delivery condition for retained findings includes ordinary and EOL package history.
If the retained history contains only base-OS EOL records, retention due to unconfirmed identities alone does not trigger delivery.

See [Change and history decisions](diff-logic.md#comparison-baseline) for what constitutes a change and [Failed scans](scan-logic.md#scan-failures) for when results are retained.

### Delivery in full mode {#full-delivery}

`full` mode sends the current report without using diff history.

| Current state | Scan notification |
| --- | --- |
| Package findings or an EOL base OS | Sends every cycle |
| Scan failures | Sends every cycle |
| No findings or scan failures | Sends only when notifications without findings are enabled |

Even when a cycle does not meet the scan notification conditions, a remediation plan is sent if it meets the [remediation delivery conditions](#remediation-delivery).

### Weekly report delivery {#weekly-report}

In `diff` mode, a full Slack report is added to scan notifications that qualify for delivery on the configured weekly report day.

- The weekday alone does not force a scan notification
- No weekly report is sent if there are no findings or changes and notifications without findings are disabled
- No full scan report is added to a cycle that sends only a remediation plan

See [Configuration](configuration.md) for the weekday and disabling options, and [Channel reports](slack-display.md#channel-display) for what the full report includes.

## Slack thread delivery conditions {#slack-thread-delivery}

For scan notifications sent through a Slack Bot in `diff` mode, a new thread is posted when the current report contains findings and any of the following applies.

- There are changes since the previous scan
- The weekly report is due
- No valid previous report link exists, such as on the first notification
- The destination channel changed and the previous report link cannot be carried over

If the current report contains no findings, no detailed thread is posted, even when scans failed or history is retained.
No scan thread is posted for a cycle that sends only a remediation plan.

In `full` mode, the current report is posted to the channel.
Slack Incoming Webhooks do not support thread replies.

See [Thread reports](slack-display.md#thread-display) for thread placement and previous report links, and [Configuration](configuration.md) for connection settings.

## Scan notification redelivery {#scan-redelivery}

In `diff` mode, history for the next comparison is saved only after all required notifications are sent successfully.

| Delivery result | History and next cycle |
| --- | --- |
| Delivery succeeds to all destinations | Saves the current state for the next comparison |
| Delivery fails to some or all destinations | Leaves comparison history unchanged and compares against the previous history next time |
| No notification needed | Saves the current state |
| History cannot be saved after delivery | May report the same changes again because the next cycle still compares against the previous history |

Delivery to other destinations is attempted even if one destination fails.
As a result, destinations where delivery succeeded may receive the same changes again next time.

If a split Slack message or thread fails partway through, messages already posted remain.
The saved report link is not updated, and the next notification may post duplicate messages.

## Remediation plan delivery conditions {#remediation-delivery}

Remediation plan delivery is decided independently of scan notification delivery.
See [Remediation processing flow](remediation-logic.md#processing-flow) for plan generation and PR operation decisions.

### Slack delivery {#remediation-slack-delivery}

Slack remediation plans are sent by comparing their display content with the last delivered display.

- Send when the display content changes
- In `diff` mode, send on the weekly report day if there is content to display, even when unchanged
- Exclude merged PRs and PRs closed without merging from weekly notifications with unchanged display content
- Skip an unchanged weekly notification if nothing remains to display after those exclusions
- Do not send for changes to the plan generation time alone

When the display content changes, the notification includes completed PRs.
See [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks) for how to read the display.

### Webhook delivery {#remediation-webhook-delivery}

The generic webhook compares against the last delivery record independently of the Slack display.

- Send when the plan content, plan availability, or plan save-failure status changes
- Send when there are undelivered PR operations
- Send every cycle while problems that block PR writes persist
- Do not send for changes to the plan generation time alone
- Include the current remediation plan when sending a scan notification or a Slack remediation plan, even if the plan has not changed

See [Common remediation plan fields](webhook-remediation-reference.md#remediation-fields) for the data format.

### Remediation plan redelivery {#remediation-redelivery}

Delivery records for remediation plans and PR operations are handled separately from scan comparison history.

- Record delivery of the plan and the included PR operations when the notification as a whole is sent successfully
- Plans and PR operations whose delivery could not be recorded because delivery failed remain eligible for redelivery next time
- Record the delivered Slack display content when all Slack remediation plan messages are posted successfully, even if other notifications fail
- Content already sent may be resent if the delivery record cannot be saved

Resending a notification does not repeat a successful PR creation.
See [Stored files](remediation-reference.md#stored-records) for saved contents and [Matching existing PRs](remediation-logic.md#existing-pr-matching) for PR checks.
