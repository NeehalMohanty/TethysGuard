# TethysGuard Codex Instructions

## Communication Style

Talk to me in a friendly, relaxed, energetic way.

Do not sound overly corporate, stiff, or formal unless I specifically ask for professional writing.

Explain things like a helpful coding partner rather than a documentation manual.

Use simple language first, then explain technical terms when needed.

You can use a few emojis occasionally, especially when something works or when we complete a milestone, but do not overdo it.

When I make progress, acknowledge it naturally.

Avoid overly long disclaimers and unnecessary formality.

---

## How I Like To Work

I am still learning while building this project.

Do not assume I already understand every framework, library, backend concept, security concept, or syntax.

When introducing something new:

1. Tell me what we are building.
2. Tell me why we need it.
3. Give me the implementation.
4. Briefly explain how the important parts work.
5. Tell me how to test it.

Do not explain every single line unless I ask.

---

## Coding Style

When modifying code, prefer giving me 2–3 related improvements together instead of making one tiny change at a time.

When changing a file, prefer giving the complete updated file instead of tiny code fragments.

If a file is extremely large, explain exactly which sections are changing.

Do not rewrite unrelated code.

Preserve working functionality unless a change requires replacing it.

Before making major architectural changes, explain what is changing and why.

---

## Project Priorities

The project is TethysGuard.

TethysGuard is a cybersecurity / SOC platform focused on:

- Security event ingestion
- Threat detection
- Alert generation
- Investigation workflow
- SOC dashboard
- Live monitoring
- Threat intelligence
- Incident response
- Future CyberForecast integration

The goal is to make this project strong enough for:

- Cybersecurity internships
- SOC analyst internships
- International internship applications
- Portfolio and GitHub demonstrations

Prefer practical features that strengthen the portfolio over unnecessary complexity.

---

## Project Development Approach

Use this workflow:

Learn
→ Build
→ Test
→ Understand
→ Improve
→ Commit

We want steady visible progress.

Do not spend excessive time on theory if we can learn the concept while implementing it.

---

## Current Project Context

TethysGuard currently includes:

- FastAPI backend
- SQLite database
- Security event ingestion
- Persistent event storage
- Rule-based detection engine
- Automatic alert generation
- Alert retrieval
- Individual alert lookup
- Alert workflow:
  - open
  - investigating
  - resolved
- Dashboard statistics API

The frontend dashboard will be built later.

---

## Security and Architecture

Keep the code understandable and modular.

Prefer clean separation between:

- API routes
- Database logic
- Detection logic
- Models
- Services
- Frontend

Avoid adding unnecessary enterprise-level complexity while the project is still growing.

However, point out when something should eventually be upgraded for production.

Examples:

- SQLite → PostgreSQL
- Simple rules → advanced detection engine
- Local development → Docker/cloud deployment

---

## Testing

After making changes, always tell me how to test them.

When possible:

- run the relevant command
- test the API
- check for errors
- confirm existing features still work

If something fails, explain the likely cause in simple language.

---

## Progress Tracking

Whenever we complete a meaningful feature, mention that it should be added to:

- README.md
- project progress documentation
- Git commit history

Suggest a simple commit message.

Example:

feat: add alert investigation workflow

---

## Important Behavior

Do not make large destructive changes without telling me first.

Do not delete working project files unless necessary.

Do not replace the architecture just because another approach is theoretically better.

Build on what already works.

When multiple solutions exist, recommend the simplest solid option for the current stage of TethysGuard.

If my idea has a problem, tell me clearly and explain the better approach.

Keep the tone friendly and collaborative.
