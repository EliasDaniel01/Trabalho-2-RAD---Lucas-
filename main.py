import re
import threading
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime
import PyPDF2

def escolher_pdf():
    path = filedialog.askopenfilename(
        title="Escolha um arquivo PDF",
        filetypes=[("Arquivos PDF", "*.pdf"), ("Todos os arquivos", "*.*")]
    )
    if path:
        lbl_arquivo.config(text=path)
        btn_verificar.config(state='normal')

def read_pdf_text(path):
    parts = []
    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for p in reader.pages:
                t = p.extract_text()
                if t:
                    parts.append(t)
    except Exception as e:
        raise RuntimeError(f"Erro ao ler PDF: {e}")
    return "\n".join(parts)

PORTUGUESE_MONTHS = {
    'janeiro':1,'fevereiro':2,'marco':3,'março':3,'abril':4,'maio':5,'junho':6,
    'julho':7,'agosto':8,'setembro':9,'outubro':10,'novembro':11,'dezembro':12
}

def normalize(s: str) -> str:
    return s.lower().strip().replace('ç','c')\
        .replace('á','a').replace('à','a').replace('ã','a').replace('â','a')\
        .replace('é','e').replace('ê','e').replace('í','i')\
        .replace('ó','o').replace('ô','o').replace('õ','o')\
        .replace('ú','u').replace('ü','u')

def find_dates(text):
    found = set()
    # dd/mm/yyyy or dd-mm-yyyy
    for m in re.finditer(r'\b([0-3]?\d)[/\\-]([01]?\d)[/\\-](\d{4})\b', text):
        d, mo, y = m.groups()
        try:
            found.add(datetime(int(y), int(mo), int(d)).date())
        except ValueError:
            pass
    # yyyy-mm-dd
    for m in re.finditer(r'\b(\d{4})[-/](0[1-9]|1[0-2]|[1-9])[-/](0[1-9]|[12]\d|3[01]|[1-9])\b', text):
        y, mo, d = m.groups()
        try:
            found.add(datetime(int(y), int(mo), int(d)).date())
        except ValueError:
            pass
    # "25 de dezembro de 2025"
    for m in re.finditer(r'\b([0-3]?\d)\s+de\s+([A-Za-zçãéóúâêôõü]+)\s+de\s+(\d{4})\b', text, flags=re.IGNORECASE):
        d, month_name, y = m.groups()
        key = normalize(month_name)
        month = PORTUGUESE_MONTHS.get(key)
        if month:
            try:
                found.add(datetime(int(y), int(month), int(d)).date())
            except ValueError:
                pass
    return sorted(found)

def get_holidays_for_year(year):
    url = f"https://date.nager.at/api/v3/PublicHolidays/{year}/BR"
    resp = requests.get(url, headers={'accept':'application/json'}, timeout=10)
    resp.raise_for_status()
    return resp.json()

def check_dates_are_holidays(dates):
    by_year = {}
    for d in dates:
        by_year.setdefault(d.year, []).append(d)
    result = []
    for year, ds in by_year.items():
        holidays = get_holidays_for_year(year)
        hol_map = {h['date']: h for h in holidays}
        for d in ds:
            key = d.isoformat()
            if key in hol_map:
                h = hol_map[key]
                name = h.get('localName') or h.get('name') or ''
                result.append((d, name))
    return result

def verificar_feriados_thread(path):
    try:
        append_text("Lendo PDF...\n")
        text = read_pdf_text(path)
        append_text("Extraindo datas...\n")
        dates = find_dates(text)
        if not dates:
            append_text("Nenhuma data encontrada no PDF.\n")
            return
        append_text(f"{len(dates)} datas encontradas:\n")
        for d in dates:
            append_text(f" - {d.isoformat()}\n")
        append_text("Consultando API de feriados por ano...\n")
        try:
            holidays_found = check_dates_are_holidays(dates)
        except Exception as e:
            append_text(f"Erro ao consultar API: {e}\n")
            return
        if not holidays_found:
            append_text("\nNenhuma das datas é feriado (BR).\n")
        else:
            append_text("\nFeriados encontrados:\n")
            for d, name in sorted(holidays_found, key=lambda x: x[0]):
                append_text(f" - {d.isoformat()} : {name}\n")
        append_text("\nConcluído.\n")
    except Exception as e:
        append_text(f"Erro: {e}\n")

def append_text(s):
    def inner():
        txt_area.insert(tk.END, s)
        txt_area.see(tk.END)
    root.after(0, inner)

def verificar_feriados():
    path = lbl_arquivo.cget("text")
    if not path or path == "Nenhum arquivo selecionado":
        messagebox.showwarning("Aviso", "Escolha primeiro um arquivo PDF.")
        return
    btn_verificar.config(state='disabled')
    txt_area.delete('1.0', tk.END)
    t = threading.Thread(target=lambda: (verificar_feriados_thread(path), root.after(0, lambda: btn_verificar.config(state='normal'))), daemon=True)
    t.start()

def criar_interface():
    global root, lbl_arquivo, txt_area, btn_verificar
    root = tk.Tk()
    root.title("Verificador de Feriados - PDF")
    root.geometry("700x420")
    root.resizable(True, True)

    top = tk.Frame(root)
    top.pack(fill='x', padx=10, pady=8)

    btn = tk.Button(top, text="Escolher arquivo PDF", command=escolher_pdf)
    btn.pack(side='left')

    btn_verificar = tk.Button(top, text="Verificar feriados", state='disabled', command=verificar_feriados)
    btn_verificar.pack(side='left', padx=8)

    lbl_arquivo = tk.Label(top, text="Nenhum arquivo selecionado", anchor="w")
    lbl_arquivo.pack(side='left', padx=8, fill='x', expand=True)

    txt_area = scrolledtext.ScrolledText(root, wrap='word', height=20)
    txt_area.pack(padx=10, pady=(0,10), fill='both', expand=True)

    root.mainloop()

if __name__ == "__main__":
    criar_interface()