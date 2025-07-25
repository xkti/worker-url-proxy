// godawful url proxy
// Buffer for encryption
import { Buffer } from "node:buffer"

/* -- stuff you probably shouldn't touch */
// AES-GCM 256bit encryption key <<!!IMPORTANT!!>>
// JSON.stringify(await crypto.subtle.exportKey('jwk', await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"])))
const aesKey = {key_ops: ["encrypt","decrypt"],ext:true,kty:"oct",k:superSecretAES,alg:"A256GCM"}
const importedKey = await crypto.subtle.importKey("jwk", aesKey, {"name":"AES-GCM"}, false, ["encrypt","decrypt"])

// HMAC consts and functions
const encoder = new TextEncoder()
const secretKeyData = encoder.encode(superSecretHMAC)
const hmacKey = await crypto.subtle.importKey("raw", secretKeyData, { name:"HMAC", hash:"MD5" }, false, ["sign", "verify"])
function byteStringToUint8Array(byteString) {
  const ui = new Uint8Array(byteString.length)
  for (let i in byteString)
    ui[i] = byteString.charCodeAt(i)
  return ui
}

// Headers for deletion
const headersToDelete = ["x-sharepointhealthscore", "docid", "etag", "ctag", "x-aspnet-version", "x-databoundary", "x-1dscollectorurl", "x-ariacollectorurl", "sprequestguid", "request-id", "ms-cv", "p3p", "x-frame-options", "microsoftsharepointteamservices", "x-download-options", "x-ms-invokeapp", "x-content-type-options", "content-security-policy", "x-cache", "x-msedge-ref", "x-networkstatistics", "x-download-options", "cache-control", "x-powered-by", "date", "spiislatency", "sprequestduration", "x-forms_based_auth_required", "x-forms_based_auth_return_url", "x-idcrl_auth_params_v1", "x-msdavext_error"]

// Regex for mime type usage. (/get.ext)
const mimes = {
  "video/mp4": new RegExp(/\.(mp4)$/),
  "video/x-matroska": new RegExp(/\.(mkv)$/),
  "audio/flac": new RegExp(/\.(flac)$/),
  "audio/ogg": new RegExp(/\.(ogg|oga|opus|spx)$/),
  "video/ogg": new RegExp(/\.(ogv)$/),
  "image/png": new RegExp(/\.(png)$/),
  "image/jpeg": new RegExp(/\.(jpg|jpeg|jfif|jfi)$/),
  "image/gif": new RegExp(/\.(gif)$/),
  "video/webm": new RegExp(/\.(webm)$/)
}
/* -- touch this instead -- */
// Redirects
const redirects = new Map([
  ["help","https://youtu.be/yD2FSwTy2lw"]
])
const baseUrl = new Map([
  ["TA","https://xxx-my.sharepoint.com/personal/admin_xxx_onmicrosoft_com/_layouts/15/download.aspx?share="],
])

const htmlFiles = new Map([
  ["", `<!DOCTYPE html><head><title>file zone</title></head><body><p>file zone</p></body>`],
])

export default {
  async fetch(request, env, ctx) {
    // Method check, only GET and HEAD is allowed.
    if (request.method !== "GET" && request.method !== "HEAD")
      return new Response("Only GET requests are allowed", { status: 405 })

    // Get pathname of request url
    let pathname = new URL(request.url).pathname.replace("/", "")
    // Get params from request url
    let reqfullurl = new URL(request.url)
    let reqparams = new URLSearchParams(reqfullurl.search)

    // Return robots.txt
    if (pathname == "robots.txt")
      return new Response(`User-agent: *\nDisallow: /`)
    // If pathname is found in htmlFiles
    if (htmlFiles.has(pathname)) {
      let editedHtml = htmlFiles.get(pathname).replace(/!TIMESTAMP!/g, new Date(Date.now()).toISOString())
      return new Response(editedHtml, { headers: {"content-type": "text/html;charset=UTF-8"}})
    }
    // Handle redirects
    if (redirects.has(pathname))
      return Response.redirect(redirects.get(pathname))

    // HMAC token generation, 1 hour
    if (pathname == "generate") {
      const expiry = Date.now() + 3600000
      const dataToAuthenticate = `${expiry}`
      const mac = await crypto.subtle.sign("HMAC", hmacKey, encoder.encode(dataToAuthenticate))
      let base64Mac = btoa(String.fromCharCode(...new Uint8Array(mac)))
      base64Mac = encodeURIComponent(base64Mac)
      return new Response(`<html><body>expires ${new Date(expiry).toISOString()}<br>?exp=${expiry}&hi=${base64Mac}</body></html>`, {headers: {"content-type": "text/html;charset=UTF-8"}})
    }

    // HMAC
    if (pathname.startsWith("private")) {
      // exp is in ms, hi is MD5 of exp
      if (!reqparams.has("exp") || !reqparams.has("hi"))
        return new Response("Private file. Please authenticate.", { status: 403 })

      const expiry = Number(reqparams.get("exp"))
      const dataToAuthenticate = `${expiry}`

      if (dataToAuthenticate == "NaN")
        return new Response("Authentication error (1)", { status: 400 })

      const receivedMacBase64 = reqparams.get("hi")
      const receivedMac = byteStringToUint8Array(atob(receivedMacBase64))
      const verified = await crypto.subtle.verify("HMAC", hmacKey, receivedMac, encoder.encode(dataToAuthenticate))

      if (!verified)
        return new Response("Authentication error (2)", { status: 400 })
      if (Date.now() > expiry)
        return new Response(`Authentication expired ${Math.round(Date.now() / 1000) - Math.round(expiry / 1000)} second(s) ago`, { status: 403 })

      var privated = "sus"
    }

    // Check if both parameters were passed
    if (!reqparams.has("id") || !reqparams.has("iv"))
      return new Response("Missing ID/IV", { status: 404 })

    // Decryption function
    async function decrypt(id, iv, importedKey) {
      let decrypted = await crypto.subtle.decrypt({"name":"AES-GCM","iv":iv}, importedKey, id)
      let decoded = new TextDecoder().decode(decrypted)
      return decoded
    }
    // Convert Base64-encoded ID+IV back to ui8
    let encId = Uint8Array.from(Buffer.from(reqparams.get("id"), "base64"))
    let encIv = Uint8Array.from(Buffer.from(reqparams.get("iv"), "base64"))
    // Attempt decryption
    try { var decryptedId = await decrypt(encId, encIv, importedKey) }
    catch (e) { return new Response("Decryption failed!", { status: 400 }) }

    // time to handle id
    console.log(decryptedId)
    let splitId = decryptedId.split("!")
    console.log(`HMAC status says ${typeof privated}`)
    if (typeof privated == "undefined") {
      if (splitId[0] == "P")
        return new Response("ID is private!",{status:400})
    } else {
      if (!splitId[0] == "P") {
        return new Response("ID isn't private!",{status:400})
      } else {
        splitId.shift()
      }
    }
    console.log(splitId)

    // ID has to go first, then location
    // This *was* going to be reversed, but it would break current URLs.
    let id = splitId[0]
    let loc = splitId[1]

    var location = baseUrl.get(loc) + id
    console.log(location)
    // If location exists
    if (location) {
      // Allow range header for partial downloads
      let newHeaders = new Headers
      if (request.headers.get("range"))
        newHeaders.append("range", request.headers.get("range"))

      // Fetch URL from location with headers
      let init = { headers: newHeaders }
      let response = await fetch(location, init)

      // If Sharepoint link returns HTML, immediately error out.
      // Error page contains sensitive info.
      if (response.headers.get("content-type") == "text/html; charset=utf-8") {
        if (!pathname.includes("html"))
          return new Response("Unexpected response from server! If this error persists, try again in an hour.", { status: 500, headers: {"content-type": "text/plain"}})
      }
      // Create new response from original so we can modify it
      let newResponse = new Response(response.body, response)

      // Remove and set headers
      for (let i in headersToDelete)
        newResponse.headers.delete(headersToDelete[i])
      newResponse.headers.set("access-control-allow-origin", "*")

      // Set content-type header if file ext is found
      for (let type in mimes) {
        if (mimes[type].test(pathname)) {
          newResponse.headers.set("content-type", type)
          break
        }
      }

      // If request URL ends with ?stream, set c-d header to inline to allow streaming
      // Requires MIME to be set, check regex.mjs
      if (reqparams.has("stream"))
        newResponse.headers.set("content-disposition", "inline")
/* TOFIX: Discord embedding
      if (request.headers.get('user-agent').toLowerCase().includes('discord')) {
        console.log("wtffffffff")
        if (regex.png.test(pathname) || regex.jpg.test(pathname) || regex.gif.test(pathname))
          return new Response(`<html><meta property="twitter:card" content="summary_large_image"><meta property="twitter:image" content="https://z.tess.eu.org/${pathname}"></html>`, { headers: {'content-type': 'text/html;charset=UTF-8'}})
        if (regex.video.test(pathname))
          return new Response(`<html><meta property="og:image" content="https://reddit.com/static/pixel.png"><meta property="og:type" content="video.other"><meta property="og:video:url" content="https://z.tess.eu.org/${pathname}"><meta property="og:video:width" content="1280"><meta property="og:video:height" content="720"></html>`, { headers: {'content-type': 'text/html;charset=UTF-8'}})
      }
*/
      // Return final response
      return newResponse
    } else {
      // 404
      return new Response("404", { status: 404 })
    }
  }
}
