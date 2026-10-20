(function () {
  // Toasts : disparition automatique
  document.querySelectorAll('.toast').forEach(function (t) {
    setTimeout(function () { t.style.transition = 'opacity .25s'; t.style.opacity = '0'; setTimeout(function () { t.remove(); }, 250); }, 3200);
  });

  // Confirmation avant soumission (formulaires avec data-confirm)
  document.addEventListener('submit', function (e) {
    var msg = e.target.dataset && e.target.dataset.confirm;
    if (msg && !window.confirm(msg)) e.preventDefault();
  });

  // Recherche : envoi automatique après une courte pause
  document.querySelectorAll('input[data-autosubmit]').forEach(function (inp) {
    var timer;
    inp.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(function () { inp.form.submit(); }, 350); });
    if (inp.value) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
  });

  // Formulaire de devis : lignes dynamiques et totaux
  var form = document.getElementById('quote-form');
  if (!form) return;
  var tbody = document.getElementById('items-tbody');
  var D = (window.DECIMALS === undefined ? 2 : window.DECIMALS), F = Math.pow(10, D);
  var money = function (n) {
    return (Number(n) || 0).toLocaleString('fr-FR', { minimumFractionDigits: D, maximumFractionDigits: D }) + '\u00a0' + (window.CURRENCY || '');
  };
  var val = function (row, name) { return parseFloat(row.querySelector('[name=' + name + ']').value.replace(',', '.')) || 0; };

  function recalc() {
    var sub = 0, tva = 0;
    tbody.querySelectorAll('.item-row').forEach(function (row) {
      var line = Math.round(val(row, 'quantity') * val(row, 'unit_price') * F) / F;
      row.querySelector('.line-total').textContent = money(line);
      sub += line;
      tva += Math.round(line * val(row, 'tva_rate') / 100 * F) / F;
    });
    document.getElementById('form-subtotal').textContent = money(sub);
    document.getElementById('form-tva').textContent = money(tva);
    document.getElementById('form-total').textContent = money(sub + tva);
  }

  tbody.addEventListener('input', recalc);
  tbody.addEventListener('change', function (e) {
    if (!e.target.classList.contains('product-select')) return;
    var opt = e.target.selectedOptions[0], row = e.target.closest('.item-row');
    if (opt && opt.value) {
      row.querySelector('[name=description]').value = opt.dataset.name;
      row.querySelector('[name=unit_price]').value = opt.dataset.price;
      row.querySelector('[name=tva_rate]').value = opt.dataset.tva;
      if (!val(row, 'quantity')) row.querySelector('[name=quantity]').value = 1;
    }
    recalc();
  });
  tbody.addEventListener('click', function (e) {
    var btn = e.target.closest('.rm-line');
    if (!btn) return;
    if (tbody.querySelectorAll('.item-row').length === 1) { alert('Le devis doit contenir au moins une ligne.'); return; }
    btn.closest('.item-row').remove();
    recalc();
  });
  document.getElementById('add-line').addEventListener('click', function () {
    tbody.appendChild(document.getElementById('row-tpl').content.cloneNode(true));
    recalc();
  });
  recalc();
})();
