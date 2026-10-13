'use strict';
const KEY = 'seredix-smart-calendar:v1';
const $ = id => document.getElementById(id);
const pad = n => String(n).padStart(2, '0');
const iso = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

let events = load();            // { 'YYYY-MM-DD': [{id,title,time}] }
let view = new Date(); view.setDate(1);
let selected = iso(new Date());

function load() {
  try { return JSON.parse(localStorage.getItem(KEY)) || {}; } catch { return {}; }
}
function save() {
  try { localStorage.setItem(KEY, JSON.stringify(events)); } catch {}
}

// Smart parsing: "Lunch tomorrow 12:30", "Dentist friday 9am", "Call mom 2025-03-01 18:00"
const DAYS = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
function parseSmart(text) {
  let date = null, time = '';
  let t = text;
  const tm = t.match(/\b(\d{1,2})(?::(\d{2}))?\s*(am|pm)?\b/i);
  if (tm && (tm[2] || tm[3])) {
    let h = +tm[1]; const m = tm[2] || '00';
    if (tm[3]) { h = h % 12 + (tm[3].toLowerCase() === 'pm' ? 12 : 0); }
    time = `${pad(h)}:${m}`; t = t.replace(tm[0], ' ');
  }
  const im = t.match(/\b(\d{4}-\d{2}-\d{2})\b/);
  const now = new Date();
  if (im) { date = im[1]; t = t.replace(im[0], ' '); }
  else if (/\btomorrow\b/i.test(t)) { const d = new Date(now); d.setDate(d.getDate() + 1); date = iso(d); t = t.replace(/\btomorrow\b/i, ' '); }
  else if (/\btoday\b/i.test(t)) { date = iso(now); t = t.replace(/\btoday\b/i, ' '); }
  else {
    const i = DAYS.findIndex(d => new RegExp(`\\b${d}\\b`, 'i').test(t));
    if (i >= 0) {
      const d = new Date(now); d.setDate(d.getDate() + ((i - d.getDay() + 7) % 7 || 7));
      date = iso(d); t = t.replace(new RegExp(`\\b${DAYS[i]}\\b`, 'i'), ' ');
    }
  }
  return { title: t.replace(/\s+/g, ' ').trim(), date, time };
}

function render() {
  $('title').textContent = view.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  $('weekdays').innerHTML = DAYS.map(d => `<div>${d.slice(0, 3)}</div>`).join('');
  const start = new Date(view); start.setDate(1 - start.getDay());
  const todayIso = iso(new Date());
  const grid = $('grid'); grid.innerHTML = '';
  for (let i = 0; i < 42; i++) {
    const d = new Date(start); d.setDate(start.getDate() + i);
    const k = iso(d);
    const cell = document.createElement('div');
    cell.className = 'cell' + (d.getMonth() !== view.getMonth() ? ' other' : '') +
      (k === todayIso ? ' today' : '') + (k === selected ? ' sel' : '');
    cell.innerHTML = `<span class="num">${d.getDate()}</span>` +
      (events[k] || []).slice(0, 3).map(e => `<span class="dot"></span>`).join('');
    [...cell.querySelectorAll('.dot')].forEach((el, j) => el.textContent = `${events[k][j].time} ${events[k][j].title}`.trim());
    cell.onclick = () => { selected = k; render(); };
    grid.appendChild(cell);
  }
  renderDay();
}

function renderDay() {
  $('dayLabel').textContent = new Date(selected + 'T00:00').toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
  const list = (events[selected] || []).slice().sort((a, b) => a.time.localeCompare(b.time));
  const ul = $('events'); ul.innerHTML = '';
  if (!list.length) ul.innerHTML = '<li><span>No events</span></li>';
  list.forEach(e => {
    const clash = e.time && list.some(o => o !== e && o.time === e.time);
    const li = document.createElement('li');
    if (clash) li.className = 'conflict';
    const label = document.createElement('span');
    label.textContent = `${e.time || 'all day'} — ${e.title}${clash ? ' (conflict)' : ''}`;
    const del = document.createElement('button'); del.textContent = '×'; del.setAttribute('aria-label', 'Delete');
    del.onclick = () => { events[selected] = events[selected].filter(x => x.id !== e.id); save(); render(); };
    li.append(label, del); ul.appendChild(li);
  });
}

$('form').onsubmit = ev => {
  ev.preventDefault();
  const p = parseSmart($('evTitle').value);
  if (!p.title) return;
  const date = p.date || selected;
  const time = $('evTime').value || p.time;
  (events[date] = events[date] || []).push({ id: Date.now() + Math.random(), title: p.title, time });
  save(); selected = date; view = new Date(date + 'T00:00'); view.setDate(1);
  $('hint').textContent = `Added "${p.title}" on ${date}${time ? ' at ' + time : ''}`;
  $('evTitle').value = ''; $('evTime').value = ''; render();
};
$('prev').onclick = () => { view.setMonth(view.getMonth() - 1); render(); };
$('next').onclick = () => { view.setMonth(view.getMonth() + 1); render(); };
$('today').onclick = () => { view = new Date(); view.setDate(1); selected = iso(new Date()); render(); };
render();
