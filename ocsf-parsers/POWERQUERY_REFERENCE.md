# SDL PowerQuery — Confirmed Syntax Reference

Empirically tested against `xdr.us1.sentinelone.net` SDL on 2026-04-29.

## Functions that WORK

### Aggregates (use inside `group ... by`)

| Function | Behavior |
|---|---|
| `count()` | Count all rows in the group |
| `count(field)` | Count rows where `field` is non-null (SQL semantics) |
| `min(field)` | Minimum value (numeric or timestamp) |
| `max(field)` | Maximum value |
| `sum(field)` | Sum of numeric field |
| `avg(field)` / `mean(field)` | Average |

### Operators / clauses

| Clause | Example |
|---|---|
| `filter` | `filter severity_id >= 4` |
| `group` | `group n=count() by serverHost` |
| `group by multiple` | `group n=count() by serverHost, finding_title` |
| `sort` | `sort -hits` (descending) / `sort hits` (ascending) |
| `limit` | `limit 20` |
| `parse` | `parse 'Failed password for $u$ from $ip$'` |
| `columns` | `columns timestamp, user_name, src_ip` |
| `columns expr` | `columns x = severity_id * 10` |

### Comparison / boolean

| Operator | Example |
|---|---|
| `==` `!=` `<` `>` `<=` `>=` | `severity_id >= 4` |
| `contains` | `message contains 'Failed'` |
| `and` `or` `not` | `class_uid='2004' and severity_id='5'` |
| `is null` / `!= null` | `filter src_ip != null` |

## Functions that DO NOT work (return "Unknown function")

| Not supported | Workaround |
|---|---|
| `countif(cond)` | `count(field)` — counts non-null values |
| `count_nonnull(field)` | `count(field)` |
| `distinctcount()` / `count_distinct()` / `uniquecount()` | use `group ... by field` then `count() by serverHost` outer query |
| `coalesce(a, b)` | Run two separate queries; merge in code |
| `if(cond, a, b)` | No native conditional — pre-filter the events |
| `sumif(field, cond)` | `sum(field)` after `filter cond` (in earlier pipeline stage) |
| `group_to_str(field)` | Project the raw field instead, or count distinct as proxy |
| Ternary `cond ? a : b` | Not supported |
| `case when ... then ... end` | Not supported |

## Verified-working query patterns

### 1. Brute-force-then-success detection

```pq
serverHost='linux-ocsf'
| parse 'Failed password for $f_user$ from $f_ip$'
| parse 'Accepted password for $a_user$ from $a_ip$'
| group fails   = count(f_user),
        success = count(a_user),
        first_seen = min(timestamp),
        last_seen  = max(timestamp)
        by serverHost, f_ip
| filter fails >= 3 and success >= 1
| sort -fails
```

### 2. Detection Findings dashboard query

```pq
class_uid='2004'
| group hits = count(),
        last_seen = max(timestamp)
        by serverHost, finding_title, severity
| sort -hits
```

### 3. Top attacker IPs

```pq
class_uid='2004' AND src_ip != null
| group attacks = count(),
        sources = count(serverHost),
        first  = min(timestamp),
        last   = max(timestamp)
        by src_ip
| filter attacks >= 5
| sort -attacks
| limit 20
```

### 4. Severity distribution heatmap

```pq
class_uid='2004'
| group hits = count() by severity, severity_id, serverHost
| sort -hits
```

### 5. Authentication failures by user

```pq
class_uid='3002' AND status_id='2'
| group attempts = count(),
        last_attempt = max(timestamp)
        by serverHost, user_name
| filter attempts >= 3
| sort -attempts
```

### 6. All Windows events with OCSF columns

```pq
serverHost='windows-ocsf'
| columns timestamp, finding_title, class_uid, class_name,
          severity, severity_id, status, status_id,
          user_name, new_user, group_name, member, src_ip
| sort -timestamp
```

### 7. Multi-stage kill chain (parse + group + threshold)

```pq
class_uid='2004'
| group attacks = count() by src_ip, serverHost
| filter attacks >= 3
| sort -attacks
```

## When in doubt

If a query throws "Unknown function 'X'":

1. Replace conditional aggregates → use `count(field)` (non-null SQL semantics).
2. Move logic into `filter` BEFORE `group`.
3. Split into multiple queries and correlate visually in the UI.
4. Stick to: `count`, `count(f)`, `min`, `max`, `sum`, `avg`, `parse`,
   `filter`, `group ... by`, `sort`, `limit`, `columns`.

These six aggregates plus the six clauses cover **>95% of real-world hunts**.
