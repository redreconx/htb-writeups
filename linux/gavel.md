# Gavel – Linux Medium – Dynamic Rule Execution & Privilege Boundary Abuse

# Machine Overview

**Gavel** is a Linux-based medium-difficulty machine that simulates a custom-built PHP auction platform. The application exposes multiple trust boundaries between user input, business logic, and backend execution, ultimately leading to remote code execution and full system compromise.

The core weakness lies in the application’s design choices rather than a single missing patch. Unsafe dynamic evaluation of user-controlled rules, combined with improper privilege separation between application components, allows an attacker to escalate from a low-privileged web user to full root access.

This machine demonstrates how *“flexible” application features*—such as dynamic rule engines, YAML-based configuration, and runtime function creation—can become critical attack vectors when security assumptions are violated.

**Key themes:**

- Source code exposure via public repository
- Improper use of PDO leading to logic-based SQL injection
- Unsafe dynamic code execution (`runkit_function_add`)
- Privilege escalation via trusted helper utilities and configuration abuse

Assessment Context

- OS: Linux
- Difficulty: Medium
- Attack Surface: Custom PHP web application
- Primary Weaknesses:
    - Unsafe dynamic code execution
    - Logic-based SQL injection
    - Privilege boundary and configuration integrity failures

# Initial Access

Initial access was achieved through a logic flaw in the inventory sorting functionality. While the developers attempted to protect database queries using prepared statements, they failed to account for how dynamically constructed SQL components behave when user input is interpolated directly into the query structure.

Specifically, user-supplied input was used to construct a column name from the SELECT clause. Although the query used parameter binding for values, SQL identifiers such as column names cannot be safely parameterized in PDO. As a result, the application relied on manual sanitization that was insufficient to prevent injection.

This weakness was amplified by PDO’s default behavior of emulating prepared statements rather than enforcing native database-level preparation. Under this configuration, crafted input was able to alter the structure of the SQL query itself, enabling the extraction of sensitive data from the database.

Through this flaw, it was possible to enumerate user credentials and identify a privileged application account, providing the foothold required to access restricted administrative functionality within the platform.

![Figure 1: Administrative interface allowing user-controlled rule modification.](../assets/gavel/image.png)

Figure 1: Administrative interface allowing user-controlled rule modification.

# Privilege Escalation – Application to User

*(Dynamic Rule Evaluation Abuse)*

The application allowed privileged users to define custom bidding rules that were evaluated dynamically during auction activity. These rules were stored in the database and later executed as PHP code to determine whether a bid was valid.

Internally, the application relied on the `runkit_function_add()` function to create a runtime function from the stored rule logic. This design assumed that rule definitions would always contain safe mathematical expressions, but no validation or sandboxing was enforced to restrict executable behavior.

Because rule content was fully user-controlled and executed in the application context, an attacker with access to the administrative interface could inject arbitrary PHP code into the rule definition. When the bidding process triggered rule evaluation, the injected code was executed by the server, resulting in remote code execution under the web application’s user account.

This vulnerability highlights the risk of treating user-defined logic as data rather than executable code. Any system that dynamically evaluates user-supplied input without strict controls effectively grants code execution to the user.

![Figure 2: Runtime rule evaluation using runkit_function_add().](../assets/gavel/image%201.png)

Figure 2: Runtime rule evaluation using runkit_function_add().

# Privilege Escalation – User to Root

*(Trusted Utility Abuse via YAML and PHP Configuration)*

After gaining a shell as the application user, further privilege escalation was possible due to a trusted helper utility designed to manage auction items and rules. This utility processed YAML files and executed rule logic with elevated privileges, assuming that the input files were safe and well-formed.

The application environment relied on a custom PHP configuration file that restricted dangerous functions through the `disable_functions` directive. However, the rule execution mechanism still permitted filesystem write operations, allowing modification of configuration files that governed PHP’s runtime behavior.

By abusing the YAML-based submission mechanism, it was possible to inject logic that overwrote the PHP configuration file, effectively removing function restrictions. Once these safeguards were disabled, the same rule execution path could be reused to execute system-level commands with elevated privileges.

This escalation path demonstrates how defense-in-depth fails when configuration integrity is not protected. Even when dangerous functions are disabled, allowing attackers to modify the configuration that enforces those restrictions negates the intended security controls entirely.

At this stage, the attacker gains unrestricted control over the host, effectively nullifying all application-level security controls.

![Figure 4: Successful privilege escalation resulting in root-level access on the host.](../assets/gavel/image%202.png)

Figure 4: Successful privilege escalation resulting in root-level access on the host.

# Detection & Defense

### Detection Opportunities

- **Web Application Logs**
    
    Abnormal input patterns in rule definitions, including unexpected function calls or non-mathematical expressions, would indicate abuse of the dynamic rule engine.
    
- **Database Audit Logs**
    
    Inventory queries containing anomalous column selections or unexpected SQL structures could reveal logic-based injection attempts, even when parameterized queries are used.
    
- **Process Execution Monitoring**
    
    PHP spawning child processes or invoking shell-level execution during bidding activity is highly anomalous and should trigger alerts.
    
- **File Integrity Monitoring (FIM)**
    
    Unauthorized modifications to application configuration files, particularly PHP configuration files, are strong indicators of post-exploitation activity.
    
- **Application Error Logs**
    
    Errors generated during malformed rule execution or failed YAML parsing may serve as early warning signs of exploitation attempts.
    

---

### Defensive Controls & Mitigations

- **Eliminate Dynamic Code Execution**
    
    User-defined rules should be interpreted through a strict expression parser rather than executed as PHP code. Dynamic function creation in production environments should be avoided entirely.
    
- **Enforce Native Prepared Statements**
    
    Disable PDO emulation and avoid constructing SQL identifiers from user input. Whitelisting valid column names is the only safe approach when dynamic selection is required.
    
- **Harden Privilege Boundaries**
    
    Helper utilities such as `gavel-util` should operate under the least-privileged user context and never process user-controlled input with elevated privileges.
    
- **Protect Configuration Integrity**
    
    Application configuration files must be immutable to non-root users. Security controls are ineffective if the configuration enforcing them can be modified.
    
- **Reduce PHP Attack Surface**
    
    Remove unnecessary extensions such as `runkit` from production systems. High-risk functionality should not be present unless explicitly required.
    

Together, these issues highlight that partial security controls are ineffective when architectural trust boundaries and configuration integrity are not strictly enforced.
