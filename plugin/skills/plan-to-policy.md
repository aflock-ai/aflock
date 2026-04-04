---
name: plan-to-policy
description: Convert a Claude plan file into a signed .aflock policy with steps and AI evaluators. Creates acceptance criteria as a verifiable contract before implementation begins.
---

# Plan-to-Policy Skill

Convert Claude plan files into .aflock policies with verification steps and AI evaluators.

## When to Use

Use `/plan-to-policy` when:
- Starting work on a **new feature** and you have a plan with acceptance criteria
- You want **spec-driven development** where criteria are locked before implementation
- You need to create an `.aflock` policy that defines what the AI must prove it did

## Workflow

### 1. Check for Available Plans

```bash
aflock plan-to-policy --list
```

This lists plan files from both `.claude/plans/` (project-local) and `~/.claude/plans/` (global). Project-local plans are shown first.

### 2. Pick the Right Plan

If the user hasn't specified a plan, look for the most recent one relevant to the current task.

### 3. Convert Plan to Policy

```bash
aflock plan-to-policy \
  --plan ~/.claude/plans/<plan-file>.md \
  --output .aflock \
  --infer-files \
  --limits
```

### 4. Review the Generated Policy

Show the user the generated `.aflock` file. Key things to review:
- **Steps**: Are all required verification steps included?
- **AI Evaluators**: Are the PASS/FAIL prompts clear and specific?
- **File Rules**: Do the inferred file rules make sense?
- **Limits**: Are spend/turn limits appropriate?

### 5. Sign the Policy

```bash
aflock sign .aflock --key <key-path> -o .aflock.signed
```

The human must sign the policy. This creates the cryptographic commitment.

### 6. Implement

Now implement the feature. The `.aflock` policy constrains what tools you can use and what files you can access during implementation.

### 7. Verify

After implementation, verify that all attestations satisfy the policy:

```bash
aflock verify --policy .aflock
```

## Plan File Format

The parser understands these patterns in plan markdown:

### Table Format (Recommended)

```markdown
## Steps

| Step | Command | AI Evaluator Prompt |
|------|---------|---------------------|
| lint | npm run lint | |
| test | npm test | |
| uat-search | | "PASS if search input shows results" |
```

### List Format

```markdown
## Deterministic Steps
- lint: npm run lint
- test: npm test

## Acceptance Criteria
- Search input is visible on the main page
- Typing a query filters results
```

### Section Format (UAT steps)

```markdown
### uat-inbox
**AI Policy Prompt**: PASS if frames show email inbox with list of emails
```

## Merge Mode

To add steps to an existing policy without replacing it:

```bash
aflock plan-to-policy --plan plan.md --merge
```

This preserves existing tool rules, limits, and steps while adding new ones from the plan.

## AI Evaluator Prompt Guidelines

Write prompts that are:
- **Specific**: "PASS if inbox shows 3+ emails with sender names"
- **Observable**: Reference what can be seen in screenshots/outputs
- **Binary**: Clear PASS/FAIL criteria

Good:
```
PASS if the frames show:
1. Search input with query typed
2. Filtered results matching the query
3. Result count displayed
FAIL otherwise.
```

Bad:
```
Check if search works.
```

## Options Reference

| Flag | Description |
|------|-------------|
| `--plan PATH` | Path to Claude plan markdown file (required) |
| `--output PATH` | Output path for policy (default: `.aflock`) |
| `--merge` | Merge into existing policy |
| `--infer-files` | Generate files.allow from plan's referenced files |
| `--limits` | Add default spend/turn limits |
| `--model MODEL` | AI evaluator model (default: claude-opus-4-5-20251101) |
| `--list` | List available plans |
