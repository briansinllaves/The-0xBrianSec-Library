Scenario:
i maintain a main branch and create a testing branch. i would do a pull request on the testing branch, after i do my rewrite and if approved by me the maintainer it would run and not merge unless i explicitly said to

## Your setup

- You maintain **main**
    
- You create a **testing** branch
    
- You rewrite code on **testing**
    

##  What happens next

- You open a **pull request from testing → main**
    
- CI/CD runs tests **because the PR was opened or updated**
    
- **Nothing merges automatically**
    
- You, as the maintainer, must **explicitly approve and click merge**
    

## Key point

A pull request **only triggers checks**. It **never merges code by itself** unless you’ve enabled auto‑merge (which is off by default everywhere).

## Where do PR test run?
**The PR tests do** _**not**_ **run in prod.** They run in an **isolated CI environment**, unless _you_ explicitly configure something different.

## Where PR tests actually run

- They run in your **CI system’s build environment** (GitHub Actions runner, GitLab runner, Jenkins agent, Azure DevOps agent, etc.)
    
- That environment is **not prod**
    
- It’s usually a **clean VM or container** spun up just for the job
    
- It gets deleted after the job finishes
    

So nothing touches prod unless you intentionally wire it that way.

## What happens in prod?

Nothing. Prod is untouched until **after merge**, and only if your pipeline has a deploy stage.

##  Your branch scenario

- You rewrite code on **testing**
    
- You open a PR into **main**
    
- CI runs tests in its own environment
    
- You approve or reject
    
- **Prod is unaffected** unless you merge and your pipeline deploys on merge
    

## When would prod be involved?

Only if you explicitly configure:

- “deploy on merge to main”
    
- or “deploy on tag”
    
- or “deploy on release branch”
    

Otherwise, PR tests stay completely isolated.

----------------------------

## so the runner needs to be attached to a test environment to really get the scope of the code running??


**No — the runner does** _**not**_ **need to be attached to a test environment unless you** _**want**_ **integration‑level testing.**

Here’s the clean breakdown.

## What a CI runner normally does

By default, a CI runner:

- Spins up a **clean, isolated VM or container**
    
- Checks out your branch
    
- Builds it
    
- Runs tests, linting, SAST, SCA, etc.
    
- Deletes itself afterward
    

This gives you **repeatable, safe, non‑prod testing**.

That’s enough for:

- Unit tests
    
- Static analysis
    
- Dependency checks
    
- Code quality gates
    

No environment needed.

## When you _do_ need a real test environment

Only if you want to test things like:

- API calls
    
- Databases
    
- Message queues
    
- Microservices
    
- Cloud resources
    
- Integration flows
    

Then you attach the runner to:

- A **test environment**
    
- A **staging namespace**
    
- A **sandbox subscription**
    
- A **docker‑compose stack**
    
- A **Kubernetes test namespace**
    

This is optional and depends on your pipeline maturity.

##  Clean summary

- **PR tests normally run in isolated CI runners, not in prod.**
    
- **You only attach to a test environment if you need integration testing.**
    
- **Prod is untouched until you merge and deploy.**

