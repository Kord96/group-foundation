import {createServer} from "node:http";
import {readFile} from "node:fs/promises";
import {fileURLToPath} from "node:url";
import {dirname,resolve,sep,extname} from "node:path";
const here=dirname(fileURLToPath(import.meta.url));
const packages=Object.fromEntries(["hyperkey","group-core","group-admission"].map(name=>[name,resolve(dirname(fileURLToPath(import.meta.resolve(`@group-foundation/${name}`))),"..")]));
export function startServer(port=0){
  const server=createServer(async(request,response)=>{
    try{
      const pathname=new URL(request.url,"http://localhost").pathname;
      const match=/^\/dependency\/(hyperkey|group-core|group-admission)\/(.*)$/u.exec(pathname);
      const root=match?packages[match[1]]:here;
      const path=resolve(root,match?match[2]:pathname==="/"?"index.html":pathname.slice(1));
      if(!path.startsWith(root+sep))throw new Error("Invalid path");
      const body=await readFile(path);
      response.setHeader("Content-Type",({".html":"text/html",".js":"text/javascript",".mjs":"text/javascript",".wasm":"application/wasm"})[extname(path)]??"application/octet-stream");
      response.end(body);
    }catch{response.writeHead(404);response.end("Not found");}
  });
  return new Promise(resolve=>server.listen(port,"127.0.0.1",()=>resolve(server)));
}
if(process.argv[1]===fileURLToPath(import.meta.url)){const server=await startServer(Number(process.env.PORT??4173));console.log(`HyperKey qualification: http://127.0.0.1:${server.address().port}`);}
