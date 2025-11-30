# GuardRails Deep Dive: From Ground Up

*A comprehensive teaching guide to understanding the GuardRails implementation in lesson-17*

---

## Table of Contents

1. [Why GuardRails Exist](#1-why-guardrails-exist)
2. [Python Fundamentals: The Building Blocks](#2-python-fundamentals-the-building-blocks)
3. [Core Concepts](#3-core-concepts)
4. [The Data Layer: What We're Protecting Against](#4-the-data-layer-what-were-protecting-against)
5. [The Validation Pipeline: How It Works](#5-the-validation-pipeline-how-it-works)
6. [Architecture: The Big Picture](#6-architecture-the-big-picture)
7. [Practical Code Walkthroughs](#7-practical-code-walkthroughs)
8. [Integration Patterns](#8-integration-patterns)
9. [Key Takeaways](#9-key-takeaways)

---

## 1. Why GuardRails Exist

### The Problem: LLMs Are Unpredictable

Large Language Models generate text probabilistically. This means:

- They might output sensitive information (PII) that was in their training data
- They might produce malformed JSON when you need structured output
- They might exceed length limits for downstream systems
- They might hallucinate fields that don't exist

**Without guardrails**, you're flying blind—hoping the LLM behaves correctly.

### The Solution: Validation Gates

GuardRails act as **validation checkpoints** between LLM output and your application:

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  LLM Output │ ──► │  GuardRails  │ ──► │  Your App/User  │
└─────────────┘     │  Validation  │     └─────────────────┘
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  If Invalid: │
                    │  - REJECT    │
                    │  - FIX       │
                    │  - RETRY     │
                    │  - ESCALATE  │
                    └──────────────┘
```

### Real-World Analogy

Think of GuardRails like **airport security**:

| Airport Security | GuardRails |
|-----------------|------------|
| X-ray scanner | `check_pii()` - scans for dangerous content |
| Passport check | `required_fields()` - verifies identity fields exist |
| Liquid limits | `length_check()` - enforces size constraints |
| TSA agent decision | `FailAction` - what happens when check fails |

---

## 2. Python Fundamentals: The Building Blocks

Before diving into GuardRails, you need to understand four Python concepts that make the implementation possible. If you already know these, skip to [Section 3](#3-core-concepts).

### 2.1 Regular Expressions (Regex): Pattern Matching

Regex is how GuardRails **detects PII patterns** in text. Let's break down the SSN pattern:

```
Pattern: \b\d{3}-\d{2}-\d{4}\b
Example: "Customer SSN: 490-86-8668"
                        ^^^^^^^^^^^
                        This matches!
```

**Character-by-character explanation:**

| Symbol | Meaning | Example Match |
|--------|---------|---------------|
| `\b` | **Word boundary** - where a word starts/ends | Prevents matching "1490-86-8668" (extra digit) |
| `\d` | **Any digit** (0-9) | Matches `4`, `9`, `0`, etc. |
| `{3}` | **Exactly 3** of the previous | `\d{3}` = exactly 3 digits |
| `-` | **Literal hyphen** | Matches the `-` character |
| `{2}` | **Exactly 2** of the previous | `\d{2}` = exactly 2 digits |
| `{4}` | **Exactly 4** of the previous | `\d{4}` = exactly 4 digits |

**Why word boundaries matter:**

```python
import re

pattern = r"\b\d{3}-\d{2}-\d{4}\b"

# ✅ Matches - proper SSN format
re.search(pattern, "SSN: 490-86-8668")  # Match!

# ❌ No match - extra digits break word boundary
re.search(pattern, "ID: 1490-86-8668")  # No match (starts with 1490)
re.search(pattern, "SSN: 490-86-86689") # No match (ends with 86689)
```

**All PII patterns explained:**

```python
patterns = {
    # SSN: 3 digits, hyphen, 2 digits, hyphen, 4 digits
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",

    # Credit Card: 4 groups of 4 digits, separated by hyphen or space (optional)
    # [-\s]? means "hyphen OR space, zero or one time"
    "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",

    # Email: word characters + @ + domain + TLD
    # [A-Za-z0-9._%+-]+ means "one or more of these characters"
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",

    # Phone: optional +1, optional separators, area code, number
    # \(?\d{3}\)? means "optional ( + 3 digits + optional )"
    "phone": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
}
```

**How `check_pii()` uses regex:**

```python
import re

def check_pii(value: str, params: dict | None = None) -> tuple[bool, str]:
    """Returns (passed, message) - passed=True means NO PII found."""

    for pii_type, pattern in patterns.items():
        if re.search(pattern, value):
            # Found PII! Validation FAILS
            return False, f"PII detected: {pii_type} pattern found"

    # No PII found - validation PASSES
    return True, "No PII detected"
```

---

### 2.2 Pydantic BaseModel: Type-Safe Data Structures

Pydantic ensures **data integrity** at runtime. Every GuardRails class uses it.

**The problem Pydantic solves:**

```python
# Without Pydantic - no validation, bugs hide
def create_constraint(name, severity):
    return {"name": name, "severity": severity}

# This "works" but is wrong - severity should be ERROR/WARNING/INFO
bad = create_constraint("test", "CRITICAL")  # No error raised!
```

**With Pydantic:**

```python
from pydantic import BaseModel
from enum import Enum

class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class Constraint(BaseModel):
    name: str
    severity: Severity

# Now invalid data raises an error immediately
try:
    bad = Constraint(name="test", severity="CRITICAL")
except ValueError as e:
    print(e)  # "Input should be 'error', 'warning' or 'info'"
```

**Key Pydantic features used in GuardRails:**

```python
from pydantic import BaseModel, Field
from typing import Any

class Constraint(BaseModel):
    # Required field with type hint
    name: str

    # Optional field with default value
    params: dict[str, Any] | None = None

    # Field with validation and default
    severity: Severity = Field(default=Severity.ERROR)

    # Pydantic auto-generates:
    # - __init__() with validation
    # - __repr__() for debugging
    # - .model_dump() for serialization
    # - .model_validate() for deserialization

# Usage
c = Constraint(name="no_pii", severity=Severity.ERROR)
print(c.model_dump())  # {"name": "no_pii", "params": None, "severity": "error"}
```

**Why GuardRails uses BaseModel everywhere:**

| Benefit | How It Helps |
|---------|--------------|
| **Type validation** | Catches wrong types at creation time |
| **Serialization** | `.model_dump()` → JSON for traces |
| **Immutability** | `model_config = {"frozen": True}` prevents modification |
| **Documentation** | Type hints serve as inline docs |

---

### 2.3 Dynamic Dispatch with `getattr()`: String-to-Function Lookup

This is the **magic** that makes GuardRails extensible. Instead of hard-coding which function to call, the function name is stored as a string and looked up at runtime.

**The problem:**

```python
# Hard-coded approach - adding new validators requires code changes
def run_validation(check_type: str, value: str):
    if check_type == "pii":
        return check_pii(value)
    elif check_type == "length":
        return check_length(value)
    elif check_type == "json":
        return check_json(value)
    # Adding new validator = modify this function
```

**The solution with `getattr()`:**

```python
class BuiltInValidators:
    @staticmethod
    def check_pii(value: str, params: dict) -> tuple[bool, str]:
        # ... PII detection logic
        return True, "No PII"

    @staticmethod
    def check_length(value: str, params: dict) -> tuple[bool, str]:
        # ... length validation logic
        return True, "Length OK"

def run_validation(check_fn_name: str, value: str, params: dict):
    # Dynamic lookup: "pii" → check_pii
    method_name = f"check_{check_fn_name}"
    check_fn = getattr(BuiltInValidators, method_name)
    return check_fn(value, params)

# Usage
run_validation("pii", "some text", {})     # Calls check_pii()
run_validation("length", "some text", {})  # Calls check_length()
```

**How `getattr()` works:**

```python
# getattr(object, name) returns the attribute of object with that name

class Example:
    value = 42
    def greet(self):
        return "Hello"

obj = Example()

# These are equivalent:
obj.value           # 42
getattr(obj, "value")  # 42

obj.greet()         # "Hello"
getattr(obj, "greet")()  # "Hello" (note the extra () to call it)
```

**In GuardRails (`guardrails.py:273-290`):**

```python
def _run_constraint(self, input_data: Any, constraint: Constraint) -> ValidationEntry:
    # constraint.check_fn = "pii" (a string)
    # We need to call BuiltInValidators.check_pii()

    method_name = f"check_{constraint.check_fn}"  # "check_pii"
    check_fn = getattr(BuiltInValidators, method_name)  # The actual function

    # Now call it
    passed, message = check_fn(input_data, constraint.params)

    return ValidationEntry(
        constraint_name=constraint.name,
        passed=passed,
        message=message,
        # ...
    )
```

**Why this pattern is powerful:**

| Benefit | Example |
|---------|---------|
| **Configuration-driven** | Store `"pii"` in JSON, not code |
| **Extensible** | Add `check_custom()` method, use `check_fn="custom"` |
| **No switch statements** | No giant if/elif chains to maintain |
| **Plugin architecture** | Third parties can add validators |

---

### 2.4 String Enums: Type-Safe Constants

`FailAction` inherits from both `str` and `Enum`. This gives you the **safety of enums** with the **convenience of strings**.

**Plain enum problem:**

```python
from enum import Enum

class FailAction(Enum):
    REJECT = "reject"
    LOG = "log"

# Works for comparison
action = FailAction.REJECT
if action == FailAction.REJECT:
    print("Blocked!")

# But fails for JSON serialization
import json
json.dumps({"action": action})  # TypeError: Object of type FailAction is not JSON serializable
```

**String enum solution:**

```python
from enum import Enum

class FailAction(str, Enum):  # Inherit from BOTH str and Enum
    REJECT = "reject"
    LOG = "log"

action = FailAction.REJECT

# Still works for type-safe comparison
if action == FailAction.REJECT:
    print("Blocked!")

# NOW works for JSON (because it's also a string)
import json
json.dumps({"action": action})  # '{"action": "reject"}'

# Can compare directly with strings
action == "reject"  # True!
```

**How inheritance order matters:**

```python
class FailAction(str, Enum):  # str FIRST, then Enum
    REJECT = "reject"

# This means FailAction.REJECT IS-A str
isinstance(FailAction.REJECT, str)   # True
isinstance(FailAction.REJECT, Enum)  # True

# String methods work
FailAction.REJECT.upper()  # "REJECT"
```

**In GuardRails:**

```python
class FailAction(str, Enum):
    REJECT = "reject"
    FIX = "fix"
    ESCALATE = "escalate"
    LOG = "log"
    RETRY = "retry"

# Used in ValidationResult
result = ValidationResult(
    is_valid=False,
    action_taken=FailAction.REJECT,  # Type-safe
    # ...
)

# Serializes cleanly to JSON for traces
result.model_dump()
# {"is_valid": false, "action_taken": "reject", ...}
```

**Why use string enums:**

| Feature | Benefit |
|---------|---------|
| **Type safety** | IDE autocomplete, typo prevention |
| **JSON-friendly** | Direct serialization to trace files |
| **String comparison** | `action == "reject"` works |
| **Self-documenting** | Enum name describes meaning |

---

## 3. Core Concepts

### 3.1 The Building Blocks

There are **four core classes** you need to understand:

```python
# 1. Constraint - A single validation rule
Constraint(
    name="no_ssn",
    check_fn="pii",           # Maps to BuiltInValidators.check_pii()
    params={"pii_types": ["ssn"]},
    severity=Severity.ERROR,  # ERROR = blocking, WARNING = log only
    on_fail=FailAction.REJECT
)

# 2. GuardRail - A collection of constraints
GuardRail(
    name="pii_protection",
    description="Prevents PII in outputs",
    constraints=[constraint1, constraint2],
    on_fail_default=FailAction.REJECT
)

# 3. GuardRailValidator - Executes validation
validator = GuardRailValidator()
result = validator.validate(input_data, guardrail)

# 4. ValidationResult - The outcome
ValidationResult(
    is_valid=False,
    total_errors=2,
    total_warnings=1,
    action_taken=FailAction.REJECT,
    entries=[ValidationEntry(...), ...]
)
```

### 3.2 The Severity Levels

Not all validation failures are equal:

| Severity | Meaning | Default Action |
|----------|---------|----------------|
| `ERROR` | **Blocking** - Must be fixed | `REJECT` |
| `WARNING` | **Non-blocking** - Log and continue | `LOG` |
| `INFO` | **Audit only** - For compliance records | `LOG` |

### 3.3 The Fail Actions

What happens when validation fails?

| FailAction | Behavior | Use Case |
|------------|----------|----------|
| `REJECT` | Block output entirely | PII detected, invalid format |
| `FIX` | Auto-repair the output | Redact PII, truncate length |
| `RETRY` | Ask LLM to regenerate | Malformed JSON |
| `ESCALATE` | Queue for human review | Uncertain cases |
| `LOG` | Continue with warning | Minor issues |

**Code location**: `guardrails.py:79-85`

```python
class FailAction(str, Enum):
    REJECT = "reject"
    FIX = "fix"
    ESCALATE = "escalate"
    LOG = "log"
    RETRY = "retry"
```

---

## 4. The Data Layer: What We're Protecting Against

### 4.1 PII Detection: The Primary Use Case

The `pii_examples_50.json` file contains **50 test cases** with real-world PII patterns:

```json
{
  "id": "pii_001",
  "text": "Contact John at 490-86-8668 for details",
  "pii_types": ["ssn"],
  "pii_values": ["490-86-8668"],
  "context": "customer_service_transcript"
}
```

### 4.2 PII Pattern Mapping

Here's how each PII type maps to detection:

| PII Type | Example from Data | Regex Pattern in `check_pii()` |
|----------|-------------------|-------------------------------|
| **SSN** | `490-86-8668` | `\b\d{3}-\d{2}-\d{4}\b` |
| **Credit Card** | `2403-8962-2133-9727` | `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b` |
| **Email** | `matthewwilson@work.org` | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,}\b` |
| **Phone** | `+1-765-351-8041` | `\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b` |

**Code location**: `guardrails.py:649-681`

```python
@staticmethod
def check_pii(value: str, params: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Check for Personally Identifiable Information."""
    patterns = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    }
    # ... detection logic
```

### 4.3 Understanding the Test Data Structure

**File: `pii_examples_50.json`** - Test cases for validation

```json
{
  "examples": [
    {
      "id": "pii_001",
      "text": "The customer SSN is 490-86-8668",
      "pii_types": ["ssn"],
      "pii_values": ["490-86-8668"],
      "expected_detection": true,
      "context": "financial_document"
    }
  ]
}
```

**File: `agent_metadata_10.json`** - Agent policies that trigger guardrails

```json
{
  "agent_id": "invoice-processor-v2",
  "policies": [
    {
      "policy_type": "data_access",
      "policy_id": "hipaa-001",
      "constraints": {
        "pii_handling_mode": "redact",  // ← Triggers no_pii() constraint
        "allowed_fields": ["amount", "date", "vendor"]
      }
    }
  ]
}
```

### 4.4 Policy to GuardRail Conversion

The `policy_bridge.py` translates declarative policies into enforceable guardrails:

| Policy Type | Policy Constraint | Generated GuardRail |
|-------------|------------------|---------------------|
| `data_access` | `pii_handling_mode: "redact"` | `no_pii()` constraint |
| `approval_required` | `requires: ["manager"]` | `required_fields(["approval_id", "approved_by"])` |
| `rate_limit` | `max_requests: 100` | `None` (external enforcement) |

**Code location**: `policy_bridge.py:89-147`

---

## 5. The Validation Pipeline: How It Works

### 5.1 The Complete Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: Create GuardRail with Constraints                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   guardrail = GuardRail(                                        │
│       name="output_safety",                                     │
│       constraints=[                                             │
│           BuiltInValidators.no_pii(),                          │
│           BuiltInValidators.length_check(max_length=1000)      │
│       ]                                                         │
│   )                                                             │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Validator Receives Input Data                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   validator = GuardRailValidator()                              │
│   input_data = "Customer email: john@example.com, SSN: 123..."  │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Execute Each Constraint                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   for constraint in guardrail.constraints:                      │
│       # Look up the check function                              │
│       check_fn = getattr(BuiltInValidators, f"check_{fn_name}") │
│                                                                 │
│       # Run the check                                           │
│       passed, message = check_fn(input_data, constraint.params) │
│                                                                 │
│       # Create validation entry                                 │
│       entry = ValidationEntry(                                  │
│           constraint_name=constraint.name,                      │
│           passed=passed,                                        │
│           message=message,                                      │
│           severity=constraint.severity,                         │
│           input_excerpt=input_data[:100]                        │
│       )                                                         │
│       self._trace.append(entry)                                 │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: Aggregate Results                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   result = ValidationResult(                                    │
│       is_valid = (error_count == 0),                           │
│       total_errors = error_count,                               │
│       total_warnings = warning_count,                           │
│       action_taken = determine_action(entries),                 │
│       entries = entries                                         │
│   )                                                             │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: Handle the Result                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   if result.action_taken == FailAction.REJECT:                  │
│       raise ValidationError("Output blocked")                   │
│   elif result.action_taken == FailAction.FIX:                   │
│       output = apply_fixes(output, result.entries)              │
│   elif result.action_taken == FailAction.RETRY:                 │
│       output = retry_llm_call()                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 The Constraint Execution Deep Dive

**Code location**: `guardrails.py:273-344`

```python
def validate(self, input_data: Any, guardrail: GuardRail) -> ValidationResult:
    """Execute all constraints against input data."""
    entries: list[ValidationEntry] = []

    for constraint in guardrail.constraints:
        entry = self._run_constraint(input_data, constraint)
        entries.append(entry)
        self._trace.append(entry)  # Build audit trail

    # Count errors and warnings
    error_count = sum(1 for e in entries
                      if not e.passed and e.severity == Severity.ERROR)
    warning_count = sum(1 for e in entries
                        if not e.passed and e.severity == Severity.WARNING)

    # Determine action based on failures
    action = self._determine_action(entries, guardrail)

    return ValidationResult(
        is_valid=(error_count == 0),
        total_errors=error_count,
        total_warnings=warning_count,
        action_taken=action,
        entries=entries
    )
```

### 5.3 The Check Function Lookup

The magic of extensibility—`check_fn` is a **string that maps to a static method**:

```python
def _run_constraint(self, input_data: Any, constraint: Constraint) -> ValidationEntry:
    """Execute a single constraint."""
    # Dynamic lookup: "pii" → BuiltInValidators.check_pii
    check_fn = getattr(BuiltInValidators, f"check_{constraint.check_fn}")

    # Execute the check
    passed, message = check_fn(input_data, constraint.params)

    return ValidationEntry(
        constraint_name=constraint.name,
        passed=passed,
        message=message,
        severity=constraint.severity,
        input_excerpt=str(input_data)[:100] if not passed else None
    )
```

**This pattern enables:**
- Adding new validators without modifying core code
- Custom validators via string registration
- Configuration-driven validation rules

### 5.4 Trace Generation: The Audit Trail

Every validation creates a trace entry for compliance:

```python
# After validation
validator.export_trace(Path("validation_trace.json"))
```

**Output format** (from `validation_trace.json`):

```json
{
  "exported_at": "2024-01-15T10:30:00Z",
  "total_entries": 50,
  "summary": {
    "passed": 33,
    "failed": 17,
    "pass_rate": 0.66
  },
  "entries": [
    {
      "timestamp": "2024-01-15T10:29:45Z",
      "constraint_name": "no_pii",
      "passed": false,
      "message": "PII detected: SSN pattern found",
      "severity": "error",
      "input_excerpt": "Customer SSN: 490-86-..."
    }
  ]
}
```

---

## 6. Architecture: The Big Picture

### 6.1 The Three Pillars of Explainability

Lesson-17's explainability framework has **three interconnected components**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXPLAINABILITY FRAMEWORK                      │
├─────────────────┬─────────────────┬─────────────────────────────┤
│   BlackBox      │   AgentFacts    │       GuardRails            │
│   (Recording)   │   (Declaration) │       (Enforcement)         │
├─────────────────┼─────────────────┼─────────────────────────────┤
│ WHAT happened   │ WHAT should     │ WHETHER output              │
│ during execution│ exist (policies)│ complies                    │
├─────────────────┼─────────────────┼─────────────────────────────┤
│ • Trace events  │ • Agent metadata│ • Validation rules          │
│ • Step timings  │ • Policy defs   │ • Constraint execution      │
│ • Error logs    │ • Capabilities  │ • Pass/fail results         │
└─────────────────┴────────┬────────┴─────────────────────────────┘
                           │
                           ▼
                  ┌────────────────┐
                  │ Policy Bridge  │
                  │ (Integration)  │
                  └────────────────┘
                           │
              Converts Policy → GuardRail
```

### 6.2 The Class Hierarchy

```
AgentFacts (BaseModel)
│   └─> Declares agent capabilities and policies
│
└─> Policy (BaseModel)
    │   └─> Defines what rules should apply
    │
    └─> [via policy_bridge.policy_to_guardrail()]
        │
        └─> GuardRail (BaseModel)
            │   └─> Executable validation ruleset
            │
            └─> PromptGuardRail (extends GuardRail)
                │   └─> LLM-specific: JSON parsing, output format
                │
                └─> [validated by] GuardRailValidator
                    │
                    └─> ValidationResult (BaseModel)
                        │   └─> Pass/fail with details
                        │
                        └─> [logged to] BlackBoxRecorder
                            │
                            └─> TraceEvent (BaseModel)
                                └─> Immutable audit record
```

### 6.3 The Integration Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: Agent Registration (AgentFacts)                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   registry.register(AgentFacts(                                 │
│       agent_id="invoice-extractor-v2",                          │
│       policies=[                                                │
│           Policy(                                               │
│               policy_type="data_access",                        │
│               constraints={"pii_handling_mode": "redact"}       │
│           )                                                     │
│       ]                                                         │
│   ))                                                            │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: Workflow Setup (BlackBox)                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   recorder = BlackBoxRecorder(workflow_id="inv-001")            │
│   recorder.record_task_plan(task_id, TaskPlan(...))             │
│   recorder.record_collaborators(task_id, [agent_info])          │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: Policy → GuardRail Conversion (PolicyBridge)            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   agent = registry.get("invoice-extractor-v2")                  │
│   policy = agent.get_active_policies()[0]                       │
│   guardrail = policy_to_guardrail(policy)                       │
│                                                                 │
│   # Result:                                                     │
│   GuardRail(                                                    │
│       name="data_access_hipaa-001",                             │
│       constraints=[no_pii_constraint]                           │
│   )                                                             │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: Agent Execution with Validation                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   # Agent produces output                                       │
│   output = agent.process(input_data)                            │
│                                                                 │
│   # Validate against guardrail                                  │
│   result = validator.validate(output, guardrail)                │
│                                                                 │
│   # Log to BlackBox                                             │
│   recorder.add_trace_event(                                     │
│       EventType.DECISION,                                       │
│       metadata={                                                │
│           "guardrail_name": guardrail.name,                     │
│           "is_valid": result.is_valid,                          │
│           "total_errors": result.total_errors                   │
│       }                                                         │
│   )                                                             │
│                                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: Export for Audit                                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   # Export all traces                                           │
│   recorder.export_black_box(task_id, "audit/blackbox.json")     │
│   validator.export_trace("audit/validation_trace.json")         │
│   registry.export_for_audit(["invoice-extractor-v2"],           │
│                             "audit/agent_facts.json")           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 6.4 Design Patterns Used

| Pattern | Where | Purpose |
|---------|-------|---------|
| **Bridge** | `policy_bridge.py` | Decouples declaration (AgentFacts) from enforcement (GuardRails) |
| **Factory** | `BuiltInValidators` | Creates Constraint objects via static methods |
| **Result** | `ValidationResult` | Typed success/failure container with metadata |
| **Strategy** | `FailAction` | Configurable response to validation failures |
| **Observer** | Trace logging | Every validation appends to audit trail |

---

## 7. Practical Code Walkthroughs

### 7.1 Example: Basic PII Detection

```python
from lesson_17.backend.explainability.guardrails import (
    GuardRail, GuardRailValidator, BuiltInValidators, FailAction
)

# Create a guardrail with PII detection
pii_guardrail = GuardRail(
    name="no_pii_output",
    description="Blocks outputs containing PII",
    constraints=[
        BuiltInValidators.no_pii()  # Detects SSN, CC, email, phone
    ],
    on_fail_default=FailAction.REJECT
)

# Create validator
validator = GuardRailValidator()

# Test with clean input
clean_output = "The invoice total is $1,234.56"
result = validator.validate(clean_output, pii_guardrail)
print(f"Clean: is_valid={result.is_valid}")  # True

# Test with PII
pii_output = "Customer SSN: 490-86-8668"
result = validator.validate(pii_output, pii_guardrail)
print(f"PII: is_valid={result.is_valid}")  # False
print(f"Action: {result.action_taken}")     # REJECT
```

### 7.2 Example: Multiple Constraints

```python
# Combine multiple validations
strict_guardrail = GuardRail(
    name="strict_output",
    constraints=[
        BuiltInValidators.no_pii(),
        BuiltInValidators.length_check(min_length=10, max_length=1000),
        BuiltInValidators.required_fields(["amount", "date"]),
    ],
    on_fail_default=FailAction.REJECT
)

# Validate structured output
output = {
    "amount": 1234.56,
    "date": "2024-01-15",
    "description": "Invoice payment"
}

result = validator.validate(output, strict_guardrail)
# All constraints pass → is_valid=True
```

### 7.3 Example: PromptGuardRail for LLM Outputs

```python
from lesson_17.backend.explainability.guardrails import (
    PromptGuardRail, validate_prompt_output
)

# Define expected JSON schema
llm_guardrail = PromptGuardRail(
    name="llm_json_output",
    required_output_fields=["answer", "confidence", "sources"],
    constraints=[
        BuiltInValidators.json_parseable(),
        BuiltInValidators.confidence_range(min_val=0.0, max_val=1.0),
    ],
    on_fail_default=FailAction.RETRY  # Re-prompt LLM on failure
)

# LLM output (raw string)
llm_output = '''
{
    "answer": "The capital of France is Paris",
    "confidence": 0.95,
    "sources": ["Wikipedia", "Encyclopedia Britannica"]
}
'''

# Validate
result = validate_prompt_output(llm_output, llm_guardrail)
print(f"Valid: {result.is_valid}")  # True
```

### 7.4 Example: Policy Bridge Integration

```python
from lesson_17.backend.explainability.policy_bridge import (
    policy_to_guardrail, enforce_agent_policies
)
from lesson_17.backend.explainability.agent_facts import (
    AgentFacts, Policy, AgentFactsRegistry
)

# Register agent with policy
registry = AgentFactsRegistry()
registry.register(AgentFacts(
    agent_id="invoice-processor",
    policies=[
        Policy(
            policy_type="data_access",
            policy_id="hipaa-001",
            constraints={"pii_handling_mode": "redact"}
        )
    ]
))

# Convert policy to guardrail
agent = registry.get("invoice-processor")
policy = agent.policies[0]
guardrail = policy_to_guardrail(policy)
# → GuardRail with no_pii() constraint

# Enforce all policies
results = enforce_agent_policies(
    agent_id="invoice-processor",
    registry=registry,
    validator=validator,
    output_data="Invoice amount: $500"
)
# → [("data_access_hipaa-001", True, "All constraints passed")]
```

---

## 8. Integration Patterns

### 8.1 Pattern: Validated Workflow Executor

```python
class ValidatedWorkflowExecutor:
    """Orchestrates BlackBox recording with GuardRail validation."""

    def __init__(self, workflow_id: str, recorder: BlackBoxRecorder,
                 validator: GuardRailValidator):
        self.workflow_id = workflow_id
        self.recorder = recorder
        self.validator = validator

    def execute_step_with_validation(
        self,
        step_id: str,
        agent_fn: Callable,
        input_data: Any,
        guardrail: GuardRail
    ) -> Any:
        # Record step start
        self.recorder.add_trace_event(EventType.STEP_START, {
            "step_id": step_id
        })

        try:
            # Execute agent
            output = agent_fn(input_data)

            # Validate output
            result = self.validator.validate(output, guardrail)

            # Log validation result
            self.recorder.add_trace_event(EventType.DECISION, {
                "guardrail_name": guardrail.name,
                "is_valid": result.is_valid,
                "total_errors": result.total_errors,
                "action_taken": result.action_taken.value
            })

            # Handle failure
            if not result.is_valid:
                if result.action_taken == FailAction.REJECT:
                    self.recorder.add_trace_event(EventType.ERROR, {
                        "error": "Validation failed",
                        "entries": [e.model_dump() for e in result.entries]
                    })
                    raise ValidationError(f"GuardRail {guardrail.name} rejected output")

            # Record success
            self.recorder.add_trace_event(EventType.STEP_END, {
                "step_id": step_id,
                "status": "success"
            })

            return output

        except Exception as e:
            self.recorder.add_trace_event(EventType.ERROR, {"error": str(e)})
            raise
```

### 8.2 Pattern: Self-Documenting GuardRails

```python
# Generate markdown documentation
docs = guardrail.document()
print(docs)

# Output:
"""
# GuardRail: no_pii_output

**Description:** Blocks outputs containing PII

## Constraints

### 1. no_pii
- **Severity:** ERROR
- **On Fail:** REJECT
- **Check Function:** pii
- **Parameters:** {"pii_types": ["ssn", "credit_card", "email", "phone"]}

## Default Fail Action
REJECT
"""
```

---

## 9. Key Takeaways

### 9.1 Mental Model

Think of GuardRails as a **three-layer system**:

1. **Declaration Layer** (AgentFacts) - "What rules should exist?"
2. **Conversion Layer** (PolicyBridge) - "How do rules become checks?"
3. **Enforcement Layer** (GuardRails) - "Does this output comply?"

### 9.2 When to Use What

| Scenario | Use This |
|----------|----------|
| Block PII in any output | `BuiltInValidators.no_pii()` |
| Enforce JSON structure | `PromptGuardRail` + `json_parseable()` |
| Limit response length | `length_check(max_length=N)` |
| Require specific fields | `required_fields(["field1", "field2"])` |
| Validate number ranges | `confidence_range(min_val, max_val)` |
| Custom validation | Create custom `check_fn` method |

### 9.3 Best Practices

1. **Start with ERROR severity** - Default to blocking, loosen if needed
2. **Use FIX for recoverable issues** - PII can be redacted, length can be truncated
3. **Use RETRY sparingly** - LLM retries cost money and time
4. **Always export traces** - Compliance requires audit trails
5. **Test with real data** - Use `pii_examples_50.json` patterns

### 9.4 Code References

| Component | File | Lines |
|-----------|------|-------|
| Core classes | `guardrails.py` | 1-150 |
| Validation logic | `guardrails.py` | 273-344 |
| PII detection | `guardrails.py` | 649-681 |
| Policy bridge | `policy_bridge.py` | 89-147 |
| Demo notebook | `03_guardrails_validation_traces.ipynb` | All cells |
| Test data | `pii_examples_50.json` | All |

---

## Next Steps

1. **Run the notebook**: `jupyter notebook notebooks/03_guardrails_validation_traces.ipynb`
2. **Examine traces**: `cat cache/guardrails_demo/validation_trace.json | jq .`
3. **Extend validators**: Add custom `check_fn` to `BuiltInValidators`
4. **Integrate with your agent**: Use `ValidatedWorkflowExecutor` pattern

---

*Document generated from analysis of lesson-17 GuardRails implementation*
*Last updated: 2024*
