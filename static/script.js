var _dlFile='',_dlName='',_tokens={};
function promptPwd(href,name){
  _dlFile=href;_dlName=name;
  document.getElementById('pwdTitle').textContent=String.fromCodePoint(0x1F512)+' '+name;
  document.getElementById('pwdInput').value='';
  document.getElementById('pwdInfo').textContent='';
  document.getElementById('pwdModal').classList.add('show');
  document.getElementById('pwdInput').focus();
}
function folderClick(dir){window.location.href='/b/'+dir;}
async function submitPwd(){
  var pw=document.getElementById('pwdInput').value;
  if(!pw)return;
  var btn=document.querySelector('.btn-primary');
  btn.disabled=true;
  btn.textContent='Verifying...';
  try{
    var resp=await fetch('/v/'+_dlFile,{
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded','X-Requested-With':'fetch'},
      body:'password='+encodeURIComponent(pw)
    });
    if(resp.ok){
      var tok=(await resp.text());
      _tokens[_dlFile]=tok;
      window.location.href='/s/'+encodeURIComponent(_dlFile)+'?auth='+tok;
    }else{
      document.getElementById('pwdInfo').style.color='#c0392b';
      document.getElementById('pwdInfo').textContent='Incorrect password';
      btn.disabled=false;
      btn.textContent='Verify';
      setTimeout(function(){document.getElementById('pwdInfo').textContent='';},3000);
    }
  }catch(e){
    document.getElementById('pwdInfo').style.color='#c0392b';
    document.getElementById('pwdInfo').textContent='Error: '+e.message;
    btn.disabled=false;
    btn.textContent='Verify';
  }
}
function closeModal(){document.getElementById('pwdModal').classList.remove('show');}
function pwdKeydown(e){if(e.key==='Enter')submitPwd();if(e.key==='Escape')closeModal();}
document.getElementById('pwdModal').addEventListener('click',function(e){if(e.target===this)closeModal();});

function copyDirectLink(name){
  var url=window.location.origin+'/f/'+name;
  copyToClipboard(url, event.currentTarget);
}
function copyProtectedLink(name){
  var tok=_tokens[name];
  if(!tok){alert('Please verify password first.');return;}
  var url=window.location.origin+'/d/'+name+'?auth='+tok;
  copyToClipboard(url, event.currentTarget);
}
function copyToClipboard(text,btn){
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){showCopiedFeedback(btn);});
  }else{
    var ta=document.createElement('textarea');
    ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try{document.execCommand('copy');showCopiedFeedback(btn);}catch(e){}
    document.body.removeChild(ta);
  }
}
function showCopiedFeedback(btn){
  if(!btn)return;
  var orig=btn.innerHTML;
  btn.innerHTML='&#10003;';
  btn.style.background='#00b894'; btn.style.color='#fff';
  setTimeout(function(){btn.innerHTML=orig; btn.style.background=''; btn.style.color='';},1500);
}
