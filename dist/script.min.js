async function postData(url = '', data = {}, success = ()=>{}, error = ()=>{}) {
  // Default options are marked with *
  return await fetch(url, {
    method: "POST", // *GET, POST, PUT, DELETE, etc.
    mode: "no-cors", // no-cors, *cors, same-origin
    cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
    credentials: "same-origin", // include, *same-origin, omit
    headers: {
      "Content-Type": "application/json",
      // 'Content-Type': 'application/x-www-form-urlencoded',
    },
    redirect: "follow", // manual, *follow, error
    referrerPolicy: "no-referrer", // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
    body: JSON.stringify(data), // body data type must match "Content-Type" header
    timeout: 30000,
  }).then((res) => {
    return res.json();
  }).then(success).catch(error);
}

document.addEventListener('DOMContentLoaded', function(){
  const redirectList = document.querySelector('#redirect-list');
  if(!redirectList){
    return;
  }

  const errorMsg = document.querySelector('#error-msg');

  let domain = document.querySelector('.domain');
  if(domain){
    domain = '.'+domain.textContent;
  }else{
    domain = '';
  }

  redirectList.querySelectorAll('.container').forEach(function(elm){
    const rmBtn = elm.querySelector('input[name="remove"]');
    if(rmBtn){
      rmBtn.addEventListener('click', function() {
        if(errorMsg){
          errorMsg.textContent = '';
        }

        elm.remove();
      });
    }
  });

  const btnNewRedirect = document.querySelector('#add-new-redirect');
  if(btnNewRedirect){
    btnNewRedirect.addEventListener('click', function() {
      if(errorMsg){
        errorMsg.textContent = '';
      }

      const randID = `checkbox_`+Math.floor(Math.random() * Math.pow(10, 8)).toString();
      console.log(randID)

      const newCont = document.createElement('div');
      newCont.classList.add('container');
      newCont.innerHTML = `
      Subdomain:<input type="text" name="subdomain" value="" placeholder="subdomain"/>${domain}
      <br/>
      Redirect:<input type="text" name="redirect" value="" placeholder="redirect"/>
      <br/>
      <input type="checkbox" id="${randID}" name="permanent"/><label for="${randID}" class="checkbox">Permanent (301)</label>
      <br/>
      <input type="button" name="remove" value="Remove">
      `;

      if(redirectList.firstElementChild){
        redirectList.insertBefore(newCont, redirectList.firstElementChild);
      }else{
        redirectList.appendChild(newCont);
      }

      const rmBtn = newCont.querySelector('input[name="remove"]');
      if(rmBtn){
        rmBtn.addEventListener('click', function() {
          if(errorMsg){
            errorMsg.textContent = '';
          }

          newCont.remove();
        });
      }
    });
  }

  const btnSaveRedirectList = document.querySelector('#save-redirect-list');
  if(btnSaveRedirectList){
    btnSaveRedirectList.addEventListener('click', function() {
      if(errorMsg){
        errorMsg.textContent = '';
      }

      const list = [];

      redirectList.querySelectorAll('.container').forEach(function(elm){
        let subdomain = elm.querySelector('input[name="subdomain"]');
        let uri = elm.querySelector('input[name="redirect"]');
        let perm = elm.querySelector('input[name="permanent"]');

        if(subdomain && uri && subdomain.value !== '' && uri.value !== ''){
          list.push({
            subdomain: subdomain.value,
            uri: uri.value,
            status: perm.checked ? 301 : 302,
          });
        }
      });

      postData('/save-redirect-list', {
        domain: domain.replace(/^\./, ''),
        list: list,
      }, function(data){
        console.log(data)

        if(errorMsg){
          if(typeof data === 'object' && data.success){
            errorMsg.textContent = 'Saved!';
          }else if(typeof data === 'object' && data.error){
            errorMsg.textContent = 'Error!\n'+data.error;
          }else{
            errorMsg.textContent = 'Error!';
          }
        }
      }, function(err){
        console.log(err)

        if(errorMsg){
          if(typeof err === 'object' && err.message){
            errorMsg.textContent = 'Error!\n'+err;
          }else{
            errorMsg.textContent = 'Error!';
          }
        }
      });
    });
  }
});

document.addEventListener('DOMContentLoaded', function(){
  const domainList = document.querySelector('#domain-list');
  if(!domainList){
    return;
  }

  const errorMsg = document.querySelector('#error-msg');

  domainList.querySelectorAll('.container').forEach(function(elm){
    const rmBtn = elm.querySelector('input[name="remove"]');
    if(rmBtn){
      rmBtn.addEventListener('click', function() {
        if(errorMsg){
          errorMsg.textContent = '';
        }

        elm.remove();
      });
    }
  });

  const btnNewDomain = document.querySelector('#add-new-domain');
  if(btnNewDomain){
    btnNewDomain.addEventListener('click', function() {
      if(errorMsg){
        errorMsg.textContent = '';
      }

      const newCont = document.createElement('div');
      newCont.classList.add('container');
      newCont.innerHTML = `
      <label>New Domain:</label><input type="text" name="domain" value="" placeholder="domain"/>
      <br/>
      <br/>
      <input type="button" name="remove" value="Remove">
      <p class="error-msg"></p>
      `;

      if(domainList.firstElementChild){
        domainList.insertBefore(newCont, domainList.firstElementChild);
      }else{
        domainList.appendChild(newCont);
      }

      const rmBtn = newCont.querySelector('input[name="remove"]');
      if(rmBtn){
        rmBtn.addEventListener('click', function() {
          if(errorMsg){
            errorMsg.textContent = '';
          }

          newCont.remove();
        });
      }
    });
  }

  function updateSavedDomainList(data = {}){
    domainList.querySelectorAll('.container input[name="domain"]').forEach(function(elm){
      let failList = [];
      if(data.failList && Array.isArray(data.failList)){
        failList = data.failList;
      }

      if(elm.value === ''){
        elm.parentNode.remove();
        return;
      }

      const elmErr = elm.parentNode.querySelector(".error-msg");
      if(elmErr){
        elmErr.textContent = '';
      }

      if(failList.includes(elm.value)){
        if(elmErr){
          elmErr.textContent = 'Error: Failed To Verify This Domain!';
        }
        return;
      }

      const label = elm.parentNode.querySelector('label');
      if(label){
        label.remove();
      }

      const uri = document.createElement('a');
      uri.href = '/'+elm.value;
      uri.textContent = elm.value;

      elm.parentNode.insertBefore(uri, elm);
      elm.remove();

      if(elmErr){
        elmErr.remove();
      }
    });
  }

  const btnSaveDomainList = document.querySelector('#save-domain-list');
  if(btnSaveDomainList){
    btnSaveDomainList.addEventListener('click', function() {
      if(errorMsg){
        errorMsg.textContent = '';
      }

      const list = [];

      domainList.querySelectorAll('.container').forEach(function(elm){
        let domain = elm.querySelector('input[name="domain"]');
        if(domain){
          if(domain.value !== ''){
            list.push(domain.value);
          }
        }else{
          domain = elm.querySelector('a[class="domain"]');
          if(domain && domain.textContent !== ''){
            list.push(domain.textContent);
          }
        }
      });

      postData('/save-domain-list', {
        list: list,
      }, function(data){
        console.log(data)

        if(errorMsg){
          if(typeof data === 'object' && data.success){
            if(data.hasFailList){
              errorMsg.textContent = 'Error: Some Domains Have Failed The Verification Process!';
            }else{
              errorMsg.textContent = 'Saved!';
            }
          }else if(typeof data === 'object' && data.error){
            errorMsg.textContent = 'Error!\n'+data.error;
          }else{
            errorMsg.textContent = 'Error!';
          }
        }

        if(typeof data === 'object' && data.success){
          updateSavedDomainList(data);
        }
      }, function(err){
        console.log(err)

        if(errorMsg){
          if(typeof err === 'object' && err.message){
            errorMsg.textContent = 'Error!\n'+err;
          }else{
            errorMsg.textContent = 'Error!';
          }
        }
      });
    });
  }
});

document.addEventListener('DOMContentLoaded', function(){
  const logoutBtn = document.querySelector('#logout');
  if(logoutBtn){
    logoutBtn.addEventListener('click', async function() {
      window.open('/logout', '_self');
    });
  }

  const backBtn = document.querySelector('#back-btn');
  if(backBtn){
    backBtn.addEventListener('click', async function() {
      window.open('/', '_self');
    });
  }

  document.querySelectorAll('.verify-redirect-input').forEach(function(elm){
    elm.addEventListener('click', function(e) {
      e.preventDefault();
      elm.select();
      document.execCommand('copy');
    });
  });
});
