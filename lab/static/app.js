let csrf='';
const el=id=>document.getElementById(id);
async function api(url,method='GET',body){
 const response=await fetch(url,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body?JSON.stringify(body):undefined});
 const data=await response.json();
 el('response').textContent=JSON.stringify({http_status:response.status,...data},null,2);
 return {response,data};
}
async function refresh(){const {data}=await api('/api/session');csrf=data.csrf;el('login-panel').hidden=!!data.customer;el('workspace').hidden=!data.customer;if(data.customer){el('identity').textContent='Pelanggan '+data.customer;const c=await api('/api/connection');el('connection').textContent='Role database: '+c.data.info?.role+' · TLS: '+(c.data.info?.ssl?'aktif':'nonaktif');await search();}}
async function search(){const {data}=await api('/api/invoices?q='+encodeURIComponent(el('query').value));el('invoices').replaceChildren();for(const row of data.invoices||[]){const tr=document.createElement('tr');for(const value of [row.id,row.customer_id,row.description,'Rp '+Number(row.amount).toLocaleString('id-ID'),row.status]){const td=document.createElement('td');td.textContent=value;tr.append(td);}el('invoices').append(tr);}}
el('login-form').addEventListener('submit',async e=>{e.preventDefault();const {response,data}=await api('/api/login','POST',{username:el('username').value,password:el('password').value});el('notice').textContent=response.ok?'Login berhasil':data.error;if(response.ok)await refresh();});
el('logout').addEventListener('click',async()=>{await api('/api/logout','POST',{});await refresh();});
el('search-form').addEventListener('submit',async e=>{e.preventDefault();await search();});
el('detail-form').addEventListener('submit',async e=>{e.preventDefault();const {response,data}=await api('/api/invoices/'+encodeURIComponent(el('invoice-id').value));el('detail').textContent=response.ok?`${data.invoice.id} · Pelanggan ${data.invoice.customer_id} · ${data.invoice.description} · Rp ${Number(data.invoice.amount).toLocaleString('id-ID')}`:data.error;});
el('demo-error').addEventListener('click',()=>api('/api/demo-error'));
refresh();
