# Remediation plans and pull requests

!!! warning "Experimental feature"

    Remediation plans and fix pull requests are experimental features. Their configuration, notifications, and PR formats may change.

## Overview {#overview}

Remediation plans propose image and dependency updates based on findings from images running with Docker and Compose.
Enabling fix pull requests also creates GitHub PRs for eligible updates.

You are responsible for checking changes, merging, pulling or building images, deploying, and checking the deployment.
For details, see [Execution scope of plans and PRs](remediation-logic.md#plan-and-pr-execution).

## Contents {#contents}

- [Enabling remediation](remediation-setup.md)
    - [Enabling remediation plans](remediation-setup.md#enable-fix-plans)
    - [Enabling fix pull requests](remediation-setup.md#enable-pull-requests)
- [When no candidate or pull request appears](remediation-troubleshooting.md)
    - [Collecting diagnostics](remediation-troubleshooting.md#collect-diagnostics)
    - [Checking for a missing plan](remediation-troubleshooting.md#check-missing-plan)
    - [Checking update failures](remediation-troubleshooting.md#check-update-failure)
    - [Checking for a missing PR](remediation-troubleshooting.md#check-missing-pr)
    - [Checking record reconciliation failures](remediation-troubleshooting.md#check-record-failure)
- [Reading the results](remediation-results.md)
    - [Remediation plans in Slack](remediation-results.md#reading-results-in-slack-and-webhooks)
    - [Interpreting update results](remediation-results.md#interpreting-updates)
    - [Finding detailed results](remediation-results.md#detailed-results)
- [How candidate selection and PR processing work](remediation-logic.md)
    - [Processing flow](remediation-logic.md#processing-flow)
    - [Image candidate selection](remediation-logic.md#image-selection)
    - [Language package candidate selection](remediation-logic.md#package-selection)
    - [Runtime selection](remediation-logic.md#runtime-and-tool-versions)
    - [Work container execution](remediation-logic.md#worker-execution)
    - [Accepting update results](remediation-logic.md#update-method-and-partial-pull-requests)
    - [PR management](remediation-logic.md#pr-management)
- [Supported formats and reason codes](remediation-reference.md)
    - [Scope and requirements](remediation-reference.md#scope-and-requirements)
    - [Supported input formats](remediation-reference.md#supported-inputs)
    - [Supported runtimes](remediation-reference.md#supported-runtimes)
    - [Result values](remediation-reference.md#result-values)
    - [Reason codes](remediation-reference.md#reason-codes)
    - [Stored records](remediation-reference.md#stored-records)

Related configuration and specifications are on the following pages.

- [Configuration: Remediation plans and fix pull requests](configuration.md#remediation)
- [How KestreLynx works: Notification conditions](how-it-works.md#notification-conditions)
- [How KestreLynx works: Generic webhook remediation fields](how-it-works.md#remediation-fields)
- [How KestreLynx works: Outbound connections](how-it-works.md#outbound-communication)
