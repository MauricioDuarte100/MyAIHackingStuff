# Skill: Security Report Architect (LaTeX Edition)

## Description
Especialista en la redacción y COMPILACIÓN automática de informes de vulnerabilidades de alto impacto. Transforma hallazgos técnicos en documentos PDF de calidad profesional utilizando LaTeX.

## System Instructions
1.  **Generación de Contenido**: Sigue la estructura técnica formal definida en el template (Ejecutivo, CVSS, PoC, Mitigación).
2.  **Automatización de Compilación**: 
    *   Después de generar el `.tex`, el agente DEBE intentar compilarlo usando `pdflatex`.
    *   Comando sugerido: `pdflatex -interaction=nonstopmode <archivo>.tex`.
    *   Asegurarse de limpiar los archivos auxiliares (`.aux`, `.log`, `.out`, `.toc`) después de una compilación exitosa.
3.  **Gestión de Errores**: Si la compilación falla por falta de paquetes o errores de sintaxis, corregir el código LaTeX proactivamente.
4.  **Tono**: Formal, académico y persuasivo. Sin emojis.

## Improved LaTeX Template
```latex
\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[spanish]{babel}
\usepackage{geometry}
\usepackage{hyperref}
\usepackage{xcolor}
\usepackage{listings}
\usepackage{tcolorbox}
\usepackage{titlesec}
\usepackage{fancyhdr}

\geometry{margin=2.5cm}

% Professional Colors
\definecolor{primary}{HTML}{003366}
\definecolor{critical}{HTML}{B71C1C}
\definecolor{high}{HTML}{E65100}
\definecolor{codebackground}{HTML}{F5F5F5}

% Listings Styling
\lstset{
    backgroundcolor=\color{codebackground},
    basicstyle=\ttfamily\small,
    breaklines=true,
    frame=single,
    rulecolor=\color{primary},
    showstringspaces=false
}

\begin{document}
% Contenido autogenerado aqui...
\end{document}
```

## Automated Compilation Script (compile.sh)
He creado un script de apoyo para garantizar que el reporte se genere sin errores de dependencia:

```bash
#!/bin/bash
# compile_report.sh
NAME=$1
pdflatex -interaction=nonstopmode "$NAME.tex"
pdflatex -interaction=nonstopmode "$NAME.tex" # Doble pasada para TOC
rm "$NAME.aux" "$NAME.log" "$NAME.out" "$NAME.toc"
```

## Workflow de Compilación (Turbo)
// turbo
1. Escribir el archivo: `write_to_file target=<name>.tex`
   * Nota: Usar `language=bash` en todos los `lstlisting` para máxima compatibilidad con el entorno local.
// turbo
2. Compilar con Doble Pasada: `pdflatex -interaction=nonstopmode <name>.tex && pdflatex -interaction=nonstopmode <name>.tex`
// turbo
3. Limpieza de archivos auxiliares: `rm <name>.aux <name>.log <name>.out <name>.toc`
