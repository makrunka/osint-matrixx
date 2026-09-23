import json
import re

import streamlit as st
from anthropic import Anthropic

# ── Page setup ────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="OSINT-Matrix",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    html, body, [class*="css"] { font-size: 17px; }
    .block-container { padding-top: 2rem; max-width: 980px; }

    .om-hero {
        border-bottom: 2px solid #1A3A5C;
        padding-bottom: 1.2rem;
        margin-bottom: 1.5rem;
    }
    .om-hero h1 {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.3rem;
        color: #14213D;
    }
    .om-hero p {
        color: #45536B;
        font-size: 1.05rem;
        margin: 0;
        line-height: 1.5;
    }

    .om-card {
        border: 1px solid #D7DDE5;
        border-radius: 10px;
        padding: 1.4rem 1.6rem;
        background: #FFFFFF;
        margin-bottom: 1.2rem;
        box-shadow: 0 1px 3px rgba(20,33,61,0.06);
    }
    .om-card .om-label {
        color: #5B6B85;
        font-size: 0.9rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        margin-bottom: 0.3rem;
    }
    .om-card .om-tool {
        font-size: 1.5rem;
        font-weight: 700;
        color: #14213D;
        margin-bottom: 0.7rem;
    }
    .om-card .om-rationale {
        color: #2B364A;
        font-size: 1.05rem;
        margin-bottom: 1rem;
        line-height: 1.55;
    }
    .om-card .om-risknote {
        color: #5B6B85;
        font-size: 0.92rem;
    }
    .om-card ol {
        margin: 0.4rem 0 0;
        padding-left: 1.3rem;
        color: #2B364A;
        font-size: 1rem;
        line-height: 1.8;
    }

    .om-risk {
        display: inline-block;
        font-size: 0.88rem;
        font-weight: 700;
        letter-spacing: 0.02em;
        padding: 5px 14px;
        border-radius: 5px;
        margin-bottom: 0.9rem;
    }
    .om-risk-high { background: #FDE8E8; color: #A6291C; border: 1px solid #F3B6B1; }
    .om-risk-medium { background: #FFF3DC; color: #91600A; border: 1px solid #F5D28A; }
    .om-risk-low { background: #E4F5E9; color: #1A7A41; border: 1px solid #A9DFBB; }

    .om-scores {
        display: flex;
        gap: 28px;
        flex-wrap: wrap;
        padding: 0.9rem 0;
        margin: 0.6rem 0 1rem;
        border-top: 1px solid #EBEEF2;
        border-bottom: 1px solid #EBEEF2;
    }
    .om-score-block { min-width: 130px; }
    .om-score-label { font-size: 0.85rem; color: #5B6B85; margin-bottom: 4px; }
    .om-score-value { font-size: 0.95rem; font-weight: 700; color: #14213D; margin-bottom: 4px; }
    .om-dots { letter-spacing: 3px; font-size: 1.1rem; }
    .om-dot-filled { color: #1A3A5C; }
    .om-dot-empty { color: #D7DDE5; }

    .om-quickbtn button {
        width: 100%;
        text-align: left !important;
        border: 1.5px solid #D7DDE5 !important;
        background: #FFFFFF !important;
        color: #14213D !important;
        font-size: 1rem !important;
        font-weight: 600 !important;
        padding: 0.7rem 1rem !important;
    }
    .om-quickbtn button:hover {
        border-color: #1A3A5C !important;
        background: #F3F6FA !important;
    }

    .om-matrix-table { width: 100%; border-collapse: collapse; font-size: 1rem; }
    .om-matrix-table th {
        text-align: left; padding: 10px 14px; background: #14213D; color: #FFFFFF;
        font-size: 0.88rem; text-transform: uppercase; letter-spacing: 0.02em;
    }
    .om-matrix-table td { padding: 12px 14px; border-bottom: 1px solid #EBEEF2; color: #2B364A; }
    .om-matrix-table tr:last-child td { border-bottom: none; }
    .om-matrix-table .om-matrix-tool { font-weight: 700; color: #14213D; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Knowledge base (єдине джерело даних для рекомендацій і матриці) ───────

KNOWLEDGE_BASE = {
    1: {
        "label": "Аналіз тексту, переписки, нікнеймів",
        "tool": "Claude AI",
        "risk_level": "high",
        "risk_note": "Хмарний сервіс: без ручного відключення дані запиту за "
                      "замовчуванням можуть використовуватися для тренування моделі.",
        "rationale": "Категорія охоплює психолінгвістичний аналіз, розпізнавання "
                      "сленгу та структурування неформатованого тексту.",
        "scores": {"Швидкість": 4, "Точність": 5, "OpSec": 0},
        "steps": [
            "Відкрити claude.ai та увійти в обліковий запис установи",
            "Вставити текст повідомлення або нікнейм у чат",
            "Сформулювати задачу аналізу (наприклад, «проаналізуй психолінгвістично цей текст»)",
            "Розглядати отримані гіпотези як припущення, що потребують незалежної перевірки, а не факт",
        ],
    },
    2: {
        "label": "Пошук особи за фото обличчя",
        "tool": "PimEyes / FaceCheck.id",
        "risk_level": "high",
        "risk_note": "Хмарна індексація облич без можливості self-hosted розгортання; "
                      "результати доступні будь-кому з доступом до сервісу.",
        "rationale": "Категорія охоплює біометричний пошук за фотографією обличчя "
                      "серед відкритих джерел.",
        "scores": {"Швидкість": 4, "Точність": 2, "OpSec": 1},
        "steps": [
            "Відкрити pimeyes.com або facecheck.id",
            "Завантажити фото лише за наявності законних підстав для пошуку",
            "Запустити безкоштовний пошук за зображенням",
            "Перевірити кожен знайдений збіг вручну — автоматичний результат не є доказом",
        ],
    },
    3: {
        "label": "Визначення локації фото без метаданих",
        "tool": "Picarta.ai",
        "risk_level": "high",
        "risk_note": "Хмарний сервіс комп'ютерного зору без self-hosted альтернативи.",
        "rationale": "Категорія охоплює геолокацію зображення за візуальними ознаками "
                      "(архітектура, рослинність, вивіски) без опори на EXIF-метадані.",
        "scores": {"Швидкість": 4, "Точність": 4, "OpSec": 1},
        "steps": [
            "Відкрити picarta.ai",
            "Завантажити фото без прив'язаних GPS-метаданих",
            "Обрати «Search Worldwide» для результату без географічних підказок",
            "Звірити видану локацію з іншими джерелами перед остаточним висновком",
        ],
    },
    4: {
        "label": "Автономне багатоетапне розслідування",
        "tool": "AI Agent Orchestration (напр. OpenOSINT)",
        "risk_level": "medium",
        "risk_note": "Помірний ризик: допускає self-hosted розгортання, але окремі "
                      "виклики все одно йдуть до зовнішніх API.",
        "rationale": "Категорія охоплює задачі, що вимагають автономного ланцюжка дій "
                      "(кілька джерел, кілька кроків) без покрокового керування аналітиком.",
        "scores": {"Швидкість": 4, "Точність": None, "OpSec": 3},
        "steps": [
            "Встановити середовище (Python або хмарне на кшталт Google Colab)",
            "Налаштувати доступ до Anthropic API",
            "Сформулювати цільовий ідентифікатор (email або юзернейм) для розслідування",
            "Розглядати відсутність результату як можливе обмеження інструментів, а не підтверджену відсутність даних",
        ],
    },
}

RISK_TEXT = {"high": "ВИСОКИЙ ОПЕРАЦІЙНИЙ РИЗИК", "medium": "ПОМІРНИЙ ОПЕРАЦІЙНИЙ РИЗИК", "low": "НИЗЬКИЙ ОПЕРАЦІЙНИЙ РИЗИК"}
RISK_CLASS = {"high": "om-risk-high", "medium": "om-risk-medium", "low": "om-risk-low"}


def dots_html(score, max_score=5):
    if score is None:
        return '<span style="color:#5B6B85;">н/д — недостатньо даних для оцінки</span>'
    filled = "●" * score
    empty = "●" * (max_score - score)
    return (f'<span class="om-dots"><span class="om-dot-filled">{filled}</span>'
            f'<span class="om-dot-empty">{empty}</span></span>')


def render_recommendation(category_id: int, reasoning: str | None = None):
    entry = KNOWLEDGE_BASE.get(category_id)
    if entry is None:
        st.warning(
            "Задача не підпадає під жодну з чотирьох категорій бази правил. "
            "Уточніть формулювання або оберіть категорію вручну нижче."
        )
        return

    score_blocks = ""
    for label, val in entry["scores"].items():
        val_text = f"{val} / 5" if val is not None else "н/д"
        score_blocks += (
            f'<div class="om-score-block">'
            f'<div class="om-score-label">{label}</div>'
            f'<div class="om-score-value">{val_text}</div>'
            f'{dots_html(val)}'
            f'</div>'
        )

    steps_html = "".join(f"<li>{s}</li>" for s in entry["steps"])

    st.markdown(
        f"""
        <div class="om-card">
            <div class="om-label">{entry['label']}</div>
            <div class="om-tool">{entry['tool']}</div>
            <span class="om-risk {RISK_CLASS[entry['risk_level']]}">{RISK_TEXT[entry['risk_level']]}</span>
            <p class="om-rationale">{reasoning or entry['rationale']}</p>
            <div class="om-scores">{score_blocks}</div>
            <p class="om-risknote">{entry['risk_note']}</p>
            <ol>{steps_html}</ol>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("Повна методика оцінювання"):
        st.write(
            "Кожен інструмент оцінено за трьома критеріями: швидкістю (час "
            "виконання запиту в секундах), точністю (відповідність результату "
            "наперед відомому еталону) та рівнем операційної безпеки (чек-лист "
            "із 5 пунктів на основі політики конфіденційності сервісу). Бали "
            "отримані практичним тестуванням, а не суб'єктивною оцінкою."
        )


def render_matrix():
    rows = ""
    for cid, entry in KNOWLEDGE_BASE.items():
        cells = "".join(
            f"<td>{dots_html(v)}</td>" for v in entry["scores"].values()
        )
        rows += (
            f"<tr><td class='om-matrix-tool'>{entry['tool']}<br>"
            f"<span style='font-weight:400; color:#5B6B85; font-size:0.88rem;'>{entry['label']}</span></td>"
            f"<td><span class='om-risk {RISK_CLASS[entry['risk_level']]}'>{RISK_TEXT[entry['risk_level']]}</span></td>"
            f"{cells}</tr>"
        )
    st.markdown(
        f"""
        <table class="om-matrix-table">
            <thead>
                <tr>
                    <th>Інструмент / категорія</th>
                    <th>Операційний ризик</th>
                    <th>Швидкість</th>
                    <th>Точність</th>
                    <th>OpSec</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )
    st.caption(
        "Бали розраховано за фіксованою методикою: швидкість — час виконання "
        "запиту в секундах; точність — відповідність результату наперед відомому "
        "еталону; операційна безпека — чек-лист із 5 пунктів за політикою "
        "конфіденційності сервісу."
    )


# ── Claude-асистент: лише класифікація, без вигаданих рекомендацій ─────────

def build_system_prompt() -> str:
    lines = [
        "Ти — класифікатор задач для системи OSINT-Matrix.",
        "Твоя єдина функція — визначити, до якої з чотирьох категорій нижче "
        "належить задача аналітика, і коротко (1-2 речення) пояснити чому, "
        "спираючись на формулювання задачі.",
        "",
        "Категорії (НІКОЛИ не змінюй назви інструментів і не додавай категорій поза списком):",
    ]
    for cid, entry in KNOWLEDGE_BASE.items():
        lines.append(f"{cid}. {entry['label']} → {entry['tool']}")
    lines += [
        "",
        "Якщо задача не підпадає під жодну категорію — постав category: 0 і чесно "
        "напиши це в reasoning, не намагайся підібрати найближчу.",
        "",
        "Відповідай ВИКЛЮЧНО у форматі JSON, без пояснень поза ним:",
        '{"category": <0-4>, "reasoning": "<1-2 речення українською>"}',
    ]
    return "\n".join(lines)


def classify_task(user_text: str) -> dict:
    api_key = st.secrets.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"category": None, "reasoning": None,
                 "error": "У secrets застосунку не задано ANTHROPIC_API_KEY."}

    client = Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            system=build_system_prompt(),
            messages=[{"role": "user", "content": user_text}],
        )
        raw = response.content[0].text.strip()
        raw = re.sub(r"^```(json)?|```$", "", raw, flags=re.MULTILINE).strip()
        parsed = json.loads(raw)
        cat_val = parsed.get("category")
        try:
            category = int(cat_val) if cat_val is not None else None
        except (TypeError, ValueError):
            category = None
        return {"category": category, "reasoning": parsed.get("reasoning"), "error": None}
    except json.JSONDecodeError:
        return {"category": None, "reasoning": None, "error": "Не вдалося розібрати відповідь моделі."}
    except Exception as exc:
        return {"category": None, "reasoning": None, "error": f"Помилка звернення до API: {exc}"}


# ── Хедер ────────────────────────────────────────────────────────────────

st.markdown(
    """
    <div class="om-hero">
        <h1>OSINT-Matrix</h1>
        <p>Система підтримки прийняття рішень для вибору ШІ-інструментів в OSINT-розслідуваннях.
        Рекомендація формується за формалізованою матрицею з трьох вимірюваних критеріїв —
        швидкості, точності та рівня операційної безпеки, а не довільним підбором.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if "selected_category" not in st.session_state:
    st.session_state.selected_category = None
if "messages" not in st.session_state:
    st.session_state.messages = []

tab_rec, tab_matrix = st.tabs(["Отримати рекомендацію", "Порівняльна матриця"])

with tab_rec:
    st.caption("Оберіть категорію вручну або опишіть задачу в чаті нижче")

    cols = st.columns(4)
    for i, (cid, entry) in enumerate(KNOWLEDGE_BASE.items()):
        with cols[i]:
            st.markdown('<div class="om-quickbtn">', unsafe_allow_html=True)
            if st.button(entry["label"], key=f"quick_{cid}"):
                st.session_state.selected_category = cid
            st.markdown("</div>", unsafe_allow_html=True)

    if st.session_state.selected_category:
        render_recommendation(st.session_state.selected_category)

    st.divider()

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"], avatar="🛡️" if msg["role"] == "assistant" else None):
            st.write(msg["content"])
            if msg.get("category") is not None:
                render_recommendation(msg["category"])

    user_input = st.chat_input("Опишіть свою задачу...")
    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.write(user_input)

        with st.chat_message("assistant", avatar="🛡️"):
            with st.spinner("Визначаю категорію..."):
                result = classify_task(user_input)

            if result["error"]:
                st.error(result["error"])
                st.session_state.messages.append({"role": "assistant", "content": result["error"]})
            else:
                reply_text = result["reasoning"] or "Ось відповідна категорія бази правил."
                st.write(reply_text)
                render_recommendation(result["category"])
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": reply_text,
                    "category": result["category"],
                    "reasoning": result["reasoning"],
                })

with tab_matrix:
    render_matrix()
