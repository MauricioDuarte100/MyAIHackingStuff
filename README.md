# My AI Hacking Stuff (Gemini CLI Elite Setup)

Este repositorio contiene mi configuracion personal para Google Gemini CLI, optimizada para Bug Bounty, Pentesting de Active Directory y Operaciones de Red Team.

Incluye:
- 8 Servidores MCP configurados.
- 11 Skills Especializadas (incluyendo Pentesting de AD y Linux).
- 3 Archivos de Contexto (Prompts) para definir el comportamiento de la IA.

## Guia de Instalacion

Sigue estos pasos para configurar tu entorno Gemini CLI con estos archivos.

### 1. Requisitos Previos

- Tener instalado Gemini CLI.
- Tener python3, node y npm instalados.
- Se recomienda usar Kali Linux u otro entorno similar de seguridad.

### 2. Instalacion de Contextos (Prompts)

Los archivos de contexto definen las reglas y conocimientos base de la IA.

1. Contexto de Sistema:
   Copia el archivo "prompts/system_context.md" a tu carpeta de configuracion global.
   Comando: cp prompts/system_context.md ~/.gemini/GEMINI.md

2. Contexto de Proyecto (Raiz):
   Copia el archivo "prompts/root_context.md" a tu directorio de trabajo principal (ej. /home/kali).
   Comando: cp prompts/root_context.md ~/gemini.md

3. Contexto de Active Directory:
   Si utilizas herramientas de AD, copia este archivo a tu carpeta especifica.
   Comando: cp prompts/ad_context.md ~/ActiveDirectoryPentestingMCP/gemini.md

### 3. Instalacion de Skills

Las skills permiten a la IA ejecutar tareas complejas y especializadas.

1. Crea el directorio de skills si no existe:
   Comando: mkdir -p ~/.gemini/skills

2. Copia las skills de este repositorio a tu configuracion:
   Comando: cp -r skills/* ~/.gemini/skills/

Esto instalara las skills: web-bugbounty-elite, linux-pentesting-elite y ad-pentesting-elite.

### 4. Configuracion de Servidores MCP

El archivo "config/mcp_config.json" contiene la configuracion de los servidores de herramientas.

1. Copia el archivo de configuracion:
   Comando: cp config/mcp_config.json ~/.gemini/antigravity/mcp_config.json

2. Ajuste de Rutas (Importante):
   El archivo mcp_config.json contiene rutas absolutas (ej: /home/kali/...). Debes editar este archivo y reemplazar "/home/kali" por la ruta de tu usuario actual si es diferente.
   
   Usa un editor de texto como nano o vim:
   Comando: nano ~/.gemini/antigravity/mcp_config.json

3. Dependencias:
   Asegurate de que las rutas especificadas en el JSON apunten a scripts validos en tu sistema (ej. los scripts de python o node de cada servidor MCP deben existir en las carpetas indicadas).

## Contenido

- prompts/: Contiene los archivos .md de contexto.
- skills/: Contiene los directorios de las skills personalizadas.
- config/: Contiene el archivo mcp_config.json.
