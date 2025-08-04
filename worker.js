import e404Html from './404.template.html'
const translations = {
  'de': (await import('./translations/de.txt')).default,
  'en': (await import('./translations/en.txt')).default,
  'fr': (await import('./translations/fr.txt')).default,
  'hi': (await import('./translations/hi.txt')).default,
  'cs': (await import('./translations/cs.txt')).default,
}
// The above cannot put in a loop because Wrangler (2.11) chokes on imports with dynamic names.
const indexHtml = (await import('./index.template.html')).default
  .replaceAll('\n', '')
  .replaceAll('  ', '')
  .replaceAll(': ', ':')
  .replaceAll(';}', '}')
const translateHtml = (await import('./translate.template.html')).default
  .replace('{{TEXT}}', translations['en']
    .trim()
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
  )
export default {
  fetch,
}
async function fetch(request, env) {
  const {pathname} = new URL(request.url)
  console.log('Country:', request.cf?.country)
  console.log('Accept-Language:', request.headers.get('accept-language'))
  
  let ip
  if (env.isDev) {
    ip = generateRandomIpv4OrIpv6Address()
  }
  else {
    ip = getIpAddress(request)
  }
  
  let body = ''
  let status = 200
  const headers = new Headers()
  headers.append('Content-Type', 'text/html; charset=utf-8')
  headers.append('Strict-Transport-Security', 'max-age=33333333; includeSubDomains; preload')
  switch (pathname) {
    case '/':
      body = transform(indexHtml, ip, getLang(request.headers.get('accept-language')))
      break
    case '/translate':
      body = translateHtml
      break
    default:
      status = 404
      body = e404Html
  }
  return new Response(body, {
    status,
    headers,
  })
}

function getIpAddress(request) {
  // Zkusíme získat všechny možné IP adresy z různých headerů
  const cfConnectingIp = request.headers.get('cf-connecting-ip')
  const xForwardedFor = request.headers.get('x-forwarded-for')
  const xRealIp = request.headers.get('x-real-ip')
  const cfPseudoIpv4 = request.headers.get('cf-pseudo-ipv4')
  
  // Sestavíme seznam všech možných IP adres
  const allIps = []
  
  if (cfPseudoIpv4) allIps.push(cfPseudoIpv4)
  if (cfConnectingIp) allIps.push(cfConnectingIp)
  if (xRealIp) allIps.push(xRealIp)
  if (xForwardedFor) {
    xForwardedFor.split(',').forEach(ip => allIps.push(ip.trim()))
  }
  
  // Odfiltrujeme prázdné hodnoty
  const validIps = allIps.filter(ip => ip && ip !== '')
  
  console.log('All available IPs:', validIps)
  
  // Najdeme první IPv4 adresu
  for (const ip of validIps) {
    if (isIPv4(ip)) {
      console.log('Selected IPv4:', ip)
      return ip
    }
  }
  
  // Pokud nenajdeme IPv4, vezmeme první dostupnou
  const fallbackIp = validIps[0] || 'unknown'
  console.log('Fallback IP:', fallbackIp)
  return fallbackIp
}

function isIPv4(ip) {
  // Kontrola IPv4 formátu (xxx.xxx.xxx.xxx)
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  return ipv4Regex.test(ip)
}

function transform(html, ip, lang) {
  const translationLines = translations[lang].split('\n')
  html = html
    .replace('{{LANG}}', lang)
    .replaceAll(/\{\{LINE([0-9]+)\}\}/g, (all, p1) => {
      return translationLines[p1 - 1]
    })
    .replaceAll('{{IP}}', ip)
    .replace(' copyElement.value.length', ip.length)
  return html
}

function getLang(header) {
  if (!header) {
    return 'en'
  }
  header = header.toLowerCase()
  const langs = header.split(/(?:,|;)/)
  for (let lang of langs) {
    if (lang in translations) {
      return lang
    }
    const [base] = lang.split('-')
    if (base in translations) {
      return base
    }
  }
  return 'en'
}

function generateRandomIpv4OrIpv6Address() {
  // 90% šance na IPv4, pouze 10% na IPv6
  if (Math.random() < 0.9) {
    return crypto.getRandomValues(new Uint8Array(4)).join('.')
  }
  else {
    return Array.from(crypto.getRandomValues(new Uint16Array(8))).map((e) => e.toString(16)).join(':')
  }
}
