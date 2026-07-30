# patches/

## 中文

此目录仅存放无法由源码特征安装器表达、且已经过评审的版本专用补丁。公共 sandbox
实现属于 `files/`，KSU 适配与注入逻辑属于 `scripts/`；不要把生成后的内核树 diff
提交到这里。

补丁命名使用 `0001-description.patch`，按内核线放入 `5.10/`、`5.15/`、`6.1/`、
`6.6/` 或 `6.12/`。每个补丁必须说明目标上游 commit、必要性和移除条件，并能通过
`git apply --check` 与 reverse-check 保证幂等。未知或不匹配的源码必须失败，禁止模糊
应用。

## English

This directory is reserved for reviewed, version-specific changes that cannot
be represented by the source-feature installer. Common sandbox implementation
belongs under `files/`; KSU adaptation and injection logic belongs under
`scripts/`. Do not commit generated kernel-tree diffs here.

Name patches `0001-description.patch` and place them under `5.10/`, `5.15/`,
`6.1/`, `6.6/`, or `6.12/`. Each patch documents its target upstream commit,
rationale, and removal condition. It must support `git apply --check` plus a
reverse check for idempotency. Unknown or mismatched sources fail closed; fuzzy
application is not allowed.
