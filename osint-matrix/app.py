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
    .block-container { padding-top: 2.5rem; max-width: 900px; }

    .om-hero {
        border-bottom: 1px solid #30363D;
        padding-bottom: 1.2rem;
        margin-bottom: 1.6rem;
    }
    .om-hero h1 {
        font-family: 'JetBrains Mono', 'Courier New', monospace;
        font-size: 1.6rem;
        font-weight: 600;
        letter-spacing: -0.01em;
        margin-bottom: 0.3rem;
        color: #E6EDF3;
    }
    .om-hero p {
        color: #8B949E;
        font-size: 0.92rem;
        margin: 0;
    }

    .om-card {
        border: 1px solid #30363D;
        border-radius: 6px;
        padding: 1.1rem 1.3rem;
        background: #161B22;
        margin-bottom: 1rem;
    }
    .om-card .om-label {
        color: #8B949E;
        font-size: 0.78rem;
        text-transform: none;
        margin-bottom: 0.2rem;
    }
    .om-card .om-tool {
        font-size: 1.15rem;
        font-weight: 600;
        color: #E6EDF3;
        margin-bottom: 0.6rem;
    }
    .om-card .om-rationale {
        color: #C9D1D9;
        font-size: 0.9rem;
        margin-bottom: 0.9rem;
        line-height: 1.5;
    }
    .om-card ol {
        margin: 0;
        padding-left: 1.1rem;
        color: #C9D1D9;
        font-size: 0.88rem;
        line-height: 1.7;
    }

    .om-tlp {
        display: inline-block;
        font-family: 'JetBrains Mono', 'Courier New', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        letter-spacing: 0.02em;
        padding: 2px 9px;
        border-radius: 3px;
        margin-bottom: 0.7rem;
    }
    .om-tlp-red { background: #3B1416; color: #FF6B6B; border: 1px solid #5C1E22; }
    .om-tlp-amber { background: #3A2E0D; color: #FFC24B; border: 1px solid #5C4A17; }
    .om-tlp-green { background: #12301C; color: #5FE08A; border: 1px solid #1E4A2C; }

    .om-quickbtn button {
        width: 100%;
        text-align: left !important;
        border: 1px solid #30363D !important;
        background: #161B22 !important;
        color: #C9D1D9 !important;
    }
    .om-quickbtn button:hover {
        border-color: #4C8BF5 !important;
        color: #E6EDF3 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Knowledge base (single source of truth — деталізовано у Розділі 2.3) ──

KNOWLEDGE_BASE = {
    1: {
        "label": "Аналіз тексту, переписки, нікнеймів",
        "tool": "Claude AI",
        "tlp": "red",
        "risk_note": "Хмарний сервіс: без ручного відключення дані запиту за "
                      "замовчуванням можуть використовуватися для тренування моделі.",
        "rationale": "Категорія охоплює психолінгвістичний аналіз, розпізнавання "
                      "сленгу та структурування неформатованого тексту.",
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
        "tlp": "red",
        "risk_note": "Хмарна індексація облич без можливості self-hosted розгортання; "
                      "результати доступні будь-кому з доступом до сервісу.",
        "rationale": "Категорія охоплює біометричний пошук за фотографією обличчя "
                      "серед відкритих джерел.",
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
        "tlp": "red",
        "risk_note": "Хмарний сервіс комп'ютерного зору без self-hosted альтернативи.",
        "rationale": "Категорія охоплює геолокацію зображення за візуальними ознаками "
                      "(архітектура, рослинність, вивіски) без опори на EXIF-метадані.",
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
        "tlp": "amber",
        "risk_note": "Помірний ризик: допускає self-hosted розгортання, але окремі "
                      "виклики все одно йдуть до зовнішніх API.",
        "rationale": "Категорія охоплює задачі, що вимагають автономного ланцюжка дій "
                      "(кілька джерел, кілька кроків) без покрокового керування аналітиком.",
        "steps": [
            "Встановити середовище (Python або хмарне на кшталт Google Colab)",
            "Налаштувати доступ до Anthropic API",
            "Сформулювати цільовий ідентифікатор (email або юзернейм) для розслідування",
            "Розглядати відсутність результату як можливе обмеження інструментів, а не підтверджену відсутність даних",
        ],
    },
}


def render_recommendation(category_id: int, reasoning: str | None = None):
    entry = KNOWLEDGE_BASE.get(category_id)
    if entry is None:
        st.warning(
            "Задача не підпадає під жодну з чотирьох категорій бази правил. "
            "Уточніть формулювання або оберіть категорію вручну нижче."
        )
        return

    tlp_class = {"red": "om-tlp-red", "amber": "om-tlp-amber", "green": "om-tlp-green"}[entry["tlp"]]
    tlp_text = {"red": "TLP: RED — критичний ризик", "amber": "TLP: AMBER — помірний ризик",
                "green": "TLP: GREEN — низький ризик"}[entry["tlp"]]

    steps_html = "".join(f"<li>{s}</li>" for s in entry["steps"])

    st.markdown(
        f"""
        <div class="om-card">
            <div class="om-label">{entry['label']}</div>
            <div class="om-tool">{entry['tool']}</div>
            <span class="om-tlp {tlp_class}">{tlp_text}</span>
            <p class="om-rationale">{reasoning or entry['rationale']}<br>
            <span style="color:#8B949E; font-size:0.83rem;">{entry['risk_note']}</span></p>
            <ol>{steps_html}</ol>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("Наукове обґрунтування (Розділ 2.3)"):
        st.write(
            "Повна методика оцінювання за критеріями швидкості, точності та рівня "
            "операційної безпеки (чек-лист із 5 пунктів) наведена в розділі 2 "
            "супровідної наукової роботи. Ця картка відображає підсумковий "
            "висновок матриці, а не самостійну оцінку моделі."
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
        return {"category": parsed.get("category"), "reasoning": parsed.get("reasoning"), "error": None}
    except json.JSONDecodeError:
        return {"category": None, "reasoning": None, "error": "Не вдалося розібрати відповідь моделі."}
    except Exception as exc:
        return {"category": None, "reasoning": None, "error": f"Помилка звернення до API: {exc}"}


# ── Хедер ────────────────────────────────────────────────────────────────

st.markdown(
    """
    <div class="om-hero">
        <h1>OSINT-Matrix</h1>
        <p>Система підтримки прийняття рішень для вибору ШІ-інструментів
        в OSINT-розслідуваннях, з урахуванням операційної безпеки.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Ручний вибір категорії ──────────────────────────────────────────────

if "selected_category" not in st.session_state:
    st.session_state.selected_category = None
if "messages" not in st.session_state:
    st.session_state.messages = []

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

# ── Чат-асистент ─────────────────────────────────────────────────────────

for msg in st.session_state.messages:
    with st.chat_message(msg["role"], avatar="🛡️" if msg["role"] == "assistant" else None):
        st.write(msg["content"])
        if msg.get("category"):
            render_recommendation(msg["category"], reasoning=msg.get("reasoning"))

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
            render_recommendation(result["category"], reasoning=result["reasoning"])
            st.session_state.messages.append({
                "role": "assistant",
                "content": reply_text,
                "category": result["category"],
                "reasoning": result["reasoning"],
            })
