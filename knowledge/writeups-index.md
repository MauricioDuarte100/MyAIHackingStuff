# Writeups Index - Categorized Reference

Base de conocimiento de 87+ writeups de CTF y bug bounty, organizados por categoría para facilitar búsquedas.

**Ubicación**: `.antigravity/writeups/`

---

## Categorías

### 1. API Security & GraphQL
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| WRITEUP_graphql.md | GraphQL CTF - 14 flags | Introspection, BOLA, IDOR, Batching, Depth limiting, Alias attack |
| WRITEUP_apivault.md | API Security - 10 flags | JWT confusion, SSRF, Race condition, Cache poison, Prototype pollution |
| writeup_web3.md | Web challenge | API testing |
| writeup_web4.md | Web challenge | API testing |
| WRITEUP_web4.md | Web challenge | Various |

### 2. Cloud & Container Security
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| CTF_Writeup_Kubernetes.md | K8s lateral movement - 3 flags | RCE, kubectl pivoting, Token extraction, Namespace jump |
| MediCloudX_writeup.md | Cloud security | AWS misconfigs |
| MediCloudX_Labs_Part1_Writeup.md | Labs series Part 1 | Cloud security |
| WRITEUP_MediCloudX.md | MediCloudX main | Cloud vulns |
| WRITEUP_MediCloudX_Labs.md | Labs complete | Various |
| WRITEUP_MediCloudX_Research_I.md | Research I | Investigation |
| WRITEUP_MediCloudX_Research_II.md | Research II | Investigation |
| WRITEUP_MediCloudX_Data_Analytics_I.md | Data Analytics I | Data exposure |

### 3. Authentication & Authorization
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| WRITEUP_apivault.md (FLAGS 1,8,9) | Auth vulns | JWT algo confusion, Mass assignment, OAuth redirect |
| WRITEUP_login_libre.md | Login bypass | Auth bypass |
| CTF8_Identidad_Prestada.md | Identity challenge | Impersonation |

### 4. Cryptography
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| WRITEUP-padding_oracle.md | Padding Oracle | CBC attack, Byte-by-byte |
| WRITEUP-Encoder.md | Encoding | Base64, Hex, URL encoding |

### 5. Binary Exploitation / PWN
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| writeup_exploit.md | Binary exploitation | Buffer overflow |
| writeup_pwnfeelmyterror.md | PWN challenge | Exploitation |
| WRITEUP_ret3syscall.md | ROP chain | Return-to-libc, Syscall |

### 6. Reverse Engineering
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| writeup_Rev_clock_work.md | Reverse challenge | Binary analysis |
| writeup_Crackme.md | Crackme | Keygen |
| writeup_xstrings.md | Strings challenge | Static analysis |

### 7. Forensics & OSINT
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| writeup_forense.md | Digital forensics | Memory/disk analysis |
| writeup_malware_downlaod.md | Malware analysis | Behavioral analysis |
| writeup_my_hisotry.md | History challenge | Log analysis |

### 8. Web Security (General)
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| La_Trampa_Writeup.md | Web trap | Various web |
| Kopitiam_Writeup.md | Kopitiam challenge | Web vulns |
| writeup_sanity.md | Sanity check | Basic web |
| writeup_warmup.md | Warmup challenge | Basic web |
| writeup_ignition.md | Ignition | Web testing |
| WRITEUP-Blu3 luck.md | Blu3 luck | Web vulns |
| WRITEUP-Regrets.md | Regrets | Web challenge |
| WRITEUP-Regrets2.md | Regrets sequel | Web challenge |
| WRITEUP_drhouse.md | Dr House themed | Web testing |
| WRITEUP_viejopascuero.md | Themed challenge | Web vulns |
| writeup_citizen_four.md | Themed challenge | Web/OSINT |
| writeup_parasite.md | Parasitic pattern | Web vulns |
| writeup_elangelexterminador.md | Themed challenge | Web testing |
| writeup_doom.md | Doom themed | Web challenge |
| WRITEUP_hell.md | Hell challenge | Web vulns |
| WRITEUP_nothel2.md | Nothell 2 | Web challenge |
| WRITEUP-nothell.md | Nothell | Web challenge |

### 9. Steganography & Misc
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| writeup_silent_message.md | Hidden message | Steganography |
| WRITEUP_Demasiado_Ruido.md | Noise challenge | Audio stego |
| writeup-ruidosenlared.md | Network noise | Traffic analysis |
| writeup-nosignaltv.md | No signal | Media analysis |
| writeup_colors.md | Color challenge | Image analysis |
| WRITEUP_qr-codes.md | QR codes | QR analysis |
| writeup_volume.md | Volume challenge | Audio |

### 10. Network & Infrastructure
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| onion_solution.md | Onion/Tor | Network anonymity |
| writeup_chat.md | Chat service | Network protocols |
| writeup_pong.md | Network game | Protocol analysis |
| writeup-momo.md | Momo challenge | Network |

### 11. Solutions & Walkthroughs (Spanish)
| Archivo | Descripción |
|---------|-------------|
| SOLUCION.md | General solution |
| SOLUCION_1.md | Solution part 1 |
| SOLUCION_2.md | Solution part 2 |
| SOLUTIOn_3.md | Solution part 3 |
| SOLUTION.md | English solution |
| SOLUCION_thp.md | THP solution |
| SOLUCION_MERCURY.md | Mercury solution |
| SOLUCION_PATIENT_II.md | Patient II solution |
| SOLUCION_onpice.md | OnPice solution |
| SOLUCION_Y_PROXIMO_PASO.md | Solution + next steps |
| SOLUCION_DATA_ANALYTICS_II.md | Data Analytics II |
| FLAG_SOLUTION.md | Flag solution |
| flag_solution.md | Flag solution (lowercase) |
| writeup_solucion.md | Writeup solution |
| COMO_ENCONTRE_LA_FLAG.md | How I found the flag |
| silence_of the_lambsSOLUCION.md | Silence of the Lambs solution |
| chibolin_writeup.md | Chibolin writeup |

### 12. Series Writeups
| Archivo | Descripción |
|---------|-------------|
| writeup_1.md | Series part 1 |
| writeup_2.md | Series part 2 |
| writeup_3.md | Series part 3 |
| writeup_4.md | Series part 4 |
| WRITEUP_5.md | Series part 5 |
| WRITEUP_6.md | Series part 6 |
| WRITEUP_7.md | Series part 7 |
| WRITEUP_8.md | Series part 8 |
| WRITEUP_9.md | Series part 9 |
| FLAGS_1_AND_2_WRITEUP.md | Flags 1 & 2 |
| WRITEUP.md | General writeup |
| writeup.md | General writeup (lowercase) |
| reader_writeup.md | Reader writeup |
| writeup_mygift.md | MyGift writeup |

### 13. Zero Day / Leaks
| Archivo | Descripción | Técnicas Clave |
|---------|-------------|----------------|
| WRITEUP_Zero_Leaks.md | Zero leaks challenge | Info disclosure |

---

## Búsqueda por Tecnología

| Tecnología | Archivos Relevantes |
|------------|---------------------|
| GraphQL | WRITEUP_graphql.md |
| JWT | WRITEUP_apivault.md |
| Kubernetes | CTF_Writeup_Kubernetes.md |
| AWS/Cloud | MediCloudX_*.md |
| OAuth | WRITEUP_apivault.md |
| SOAP/XML | (buscar en general) |
| REST API | WRITEUP_apivault.md, writeup_web*.md |

---

## Búsqueda por Vulnerabilidad

| Vulnerabilidad | Archivos Relevantes |
|----------------|---------------------|
| IDOR/BOLA | WRITEUP_graphql.md, WRITEUP_apivault.md |
| Race Condition | WRITEUP_apivault.md (FLAG 3) |
| SSRF | WRITEUP_apivault.md (FLAG 4) |
| Cache Poisoning | WRITEUP_apivault.md (FLAG 5) |
| Prototype Pollution | WRITEUP_apivault.md (FLAG 6) |
| JWT Attacks | WRITEUP_apivault.md (FLAG 1) |
| Mass Assignment | WRITEUP_apivault.md (FLAG 8) |
| OAuth Vulns | WRITEUP_apivault.md (FLAG 9) |
| Deserialization | WRITEUP_apivault.md (FLAG 10) |
| Lateral Movement | CTF_Writeup_Kubernetes.md |
| Padding Oracle | WRITEUP-padding_oracle.md |

---

## Comandos de Búsqueda

```bash
# Buscar por tecnología
grep -rl "GraphQL\|graphql" .antigravity/writeups/
grep -rl "JWT\|jwt\|token" .antigravity/writeups/
grep -rl "Kubernetes\|kubectl\|k8s" .antigravity/writeups/

# Buscar por vulnerabilidad
grep -rl "SSRF\|ssrf" .antigravity/writeups/
grep -rl "IDOR\|idor" .antigravity/writeups/
grep -rl "race condition\|Race Condition" .antigravity/writeups/

# Extraer payloads curl
grep -A 10 "curl " .antigravity/writeups/WRITEUP_graphql.md

# Buscar flags/soluciones
grep -r "FLAG{\|flag{" .antigravity/writeups/
```

---

## Estadísticas

| Métrica | Valor |
|---------|-------|
| Total writeups | 87 |
| Categorías | 13 |
| Con técnicas documentadas | ~50 |
| Con payloads extraíbles | ~40 |
| En español | ~60% |
| En inglés | ~40% |

---

## Actualización

Para agregar un nuevo writeup:
1. Guardar en `.antigravity/writeups/[nombre].md`
2. Actualizar este índice
3. Actualizar `.antigravity/rules/writeups-integration.md` si aplica

---

**Versión**: 1.0
**Creado**: 2026-01-30
**Última actualización**: 2026-01-30
