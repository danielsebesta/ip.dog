import e404Html from './404.template.html'

const translations = {
  'de': (await import('./translations/de.txt')).default,
  'en': (await import('./translations/en.txt')).default,
  'fr': (await import('./translations/fr.txt')).default,
  'hi': (await import('./translations/hi.txt')).default,
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

  let ip
  if (env.isDev) {
    ip = '127.0.0.1'
  }
  else {
    ip = request.headers.get('cf-connecting-ip')
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
