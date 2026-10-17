import assert from "node:assert/strict";
import {chromium} from "playwright";
import {startServer} from "./server.mjs";
const server=await startServer(),browser=await chromium.launch({headless:true});
try{
  const page=await browser.newPage(),errors=[];
  page.on("pageerror",error=>{errors.push(error.message);console.error("Browser error:",error.message);});
  page.on("console",message=>{if(message.type()==="error")console.error(message.text());});
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForFunction(()=>Boolean(window.qualification),{},{timeout:10000});
  const first=await page.evaluate(()=>window.qualification.create());
  const second=await page.evaluate(()=>window.qualification.create());
  assert.notEqual(first.id,second.id);
  assert.notEqual(first.copyId,second.copyId);
  const signature=await page.evaluate(key=>window.qualification.sign(key.id,key.copyId),first);
  await page.reload();await page.waitForFunction(()=>Boolean(window.qualification));
  assert.equal((await page.evaluate(()=>window.qualification.list())).length,2);
  assert.equal(await page.evaluate(key=>window.qualification.sign(key.id,key.copyId),first),signature);
  await page.evaluate(key=>window.qualification.forget(key.id,key.copyId),first);
  assert.match(await page.evaluate(async key=>{try{await window.qualification.sign(key.id,key.copyId);return "unexpected signature";}catch(error){return error.message;}},first),/forgotten/);
  await page.reload();await page.waitForFunction(()=>Boolean(window.qualification));
  assert.equal((await page.evaluate(()=>window.qualification.list())).find(key=>key.id===first.id).status,"forgotten");
  assert.equal((await page.evaluate(()=>window.qualification.list())).find(key=>key.id===second.id).status,"ready");
  assert.deepEqual(errors,[]);
  console.log("Browser qualification passed: native founder, sealed reload, conventional signature, atomic forget, independent Copies.");
}finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
