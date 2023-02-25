const translations = {
  'de': (await import('./translations/de.txt')).default,
  'en': (await import('./translations/en.txt')).default,
  'fr': (await import('./translations/fr.txt')).default,
  'hi': (await import('./translations/hi.txt')).default,
}
// The above cannot put in a loop because Wrangler (2.11) chokes on imports with dynamic names.

export default {
  fetch,
}

const indexHtml = (await import('./index.html')).default
  .replaceAll('\n', '')
  .replaceAll('  ', '')
  .replaceAll(': ', ':')
  .replaceAll(';}', '}')

const translateHtml = (await import('./translate.html')).default
  .replace('{{TEXT}}', translations['en'].trim().replaceAll('<', '&lt;').replaceAll('>', '&gt;'))

async function fetch(request) {
  const {pathname} = new URL(request.url)
  const ip = request.headers.get('cf-connecting-ip')

  let status = 200
  const headers = {
    'Content-Type': 'text/html; charset=utf-8',
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  }
  let content = ''

  switch (pathname) {
    case '/':
      content = transform(indexHtml, ip, getLang(request.headers.get('accept-language')))
      break

    case '/translate':
      content = translateHtml
      break

    default:
      status = 404
      content = `404 page not found<br><a href="/">home page</a>`
  }

  return new Response(content, {
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
