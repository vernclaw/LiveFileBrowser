function copyLink(){
  var u = document.getElementById('dlUrl').textContent;
  navigator.clipboard ? navigator.clipboard.writeText(u).then(function(){
    showCopied();
  }) : fallbackCopy(u);
}
function fallbackCopy(u){
  var ta = document.createElement('textarea');
  ta.value = u;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try { document.execCommand('copy'); showCopied(); } catch(e) { alert('Copy failed: ' + u); }
  document.body.removeChild(ta);
}
function showCopied(){
  var btn = document.querySelector('.btn-secondary');
  var orig = btn.innerHTML;
  btn.innerHTML = '&#10003; Copied!';
  btn.style.background = '#00b894';
  btn.style.color = '#fff';
  setTimeout(function(){ btn.innerHTML = orig; btn.style.background = ''; btn.style.color = ''; }, 2000);
}
