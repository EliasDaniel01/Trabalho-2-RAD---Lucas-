# Verificador de Feriados - PDF

Pequena ferramenta em Python que permite escolher um arquivo PDF, extrair datas contidas nele e verificar quais dessas datas são feriados no Brasil consultando a API pública: `https://date.nager.at/api/v3/PublicHolidays/{ANO}/BR`.

## Estrutura
- main.py — interface Tkinter, leitura de PDF, extração de datas e verificação via API.

## Requisitos
- Python 3.8+
- Pacotes:
  - requests
  - PyPDF2

Instalar dependências:
```
py -m pip install --upgrade pip
py -m pip install requests PyPDF2
```

## Como executar
No PowerShell (ou terminal):
```
py "c:/Users/princ/Documents/trabalho 2 Lucas/main.py"
```
ou
```
python "c:/Users/princ/Documents/trabalho 2 Lucas/main.py"
```

1. Clique em "Escolher arquivo PDF".
2. Selecione o PDF que contém as datas.
3. Clique em "Verificar feriados".
4. O resultado aparecerá na área de texto da interface, listando as datas encontradas e indicando quais são feriados (com o nome do feriado).

## Formatos de data suportados
- dd/mm/yyyy ou d/m/yyyy (ex: 25/12/2025)
- dd-mm-yyyy (ex: 25-12-2025)
- yyyy-mm-dd (ex: 2025-12-25)
- Formato em português: `25 de dezembro de 2025`

## Adicionar imagem de pré-visualização (opcional)
<p align="center">
  <img src="Captura de Tela (1).png" alt="Logo" width="800"/>
</p>

## Git (opcional)
Inicializar repositório e commitar:
```
git init
git add main.py README.md
git commit -m "Primeiro commit: app verificador de feriados a partir de PDF"
```

## Observações
- A verificação de feriados é feita por ano — a API é chamada para cada ano presente nas datas extraídas.
- Se faltar o `requests` ou `PyPDF2`, instale conforme a seção Requisitos.
