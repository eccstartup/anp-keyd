/*
 * 把仓库里的 docs/DESIGN.md 引入站点。
 *
 * 这是整站唯一一处不做重写的正文:设计说明是一份"一旦发布就不能改"的记录,
 * 抄一遍等于凭空造出第二份说法,而两边迟早对不上。所以这里是**引入**,不是搬运。
 *
 * 规矩和这个工具本身一样:**认不出的就报错,不悄悄放过去。**
 * 一份链接映射没盖住的相对链接会直接让构建失败 —— 宁可构建红,也不要发布一个
 * 指向 404 的页面。
 */

import { execFileSync } from 'node:child_process'
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const source = new URL('../../docs/DESIGN.md', import.meta.url)
const target = new URL('../design/index.md', import.meta.url)

// 源码和别的仓库文档在站上没有对应的页面,所以指向 GitHub。
// 分支名写死:仓库的默认分支是 master,而构建机上通常没有本地分支可问。
const REPO = (() => {
  try {
    const url = execFileSync('git', ['remote', 'get-url', 'origin'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    const m = url.match(/github\.com[:/](.+?)(?:\.git)?$/)
    if (m) return `https://github.com/${m[1]}`
  } catch {
    // 没有 git(或没有 origin)就用兜底的那个。
  }
  return 'https://github.com/eccstartup/anp-keyd'
})()

const BRANCH = 'master'
const blob = (path) => `${REPO}/blob/${BRANCH}/${path}`

// 相对链接 → 站外地址。每一条都是显式的,新增链接必须来这里登记。
const REWRITES = [
  { pattern: /\]\((?:\.\.\/)?README\.md\)/g, to: `](${blob('README.md')})` },
  { pattern: /\]\(ADAPTER\.md\)/g, to: `](${blob('docs/ADAPTER.md')})` },
  { pattern: /\]\(TODO-archive\.md\)/g, to: `](${blob('docs/TODO-archive.md')})` },
]

// 站内已有的页面。设计说明如果哪天链到别的仓库文档,要么在 REWRITES 里登记,
// 要么在这里开一页 —— 两条都不做就构建红。
const SITE_ROUTES = new Set(['/design/', '/'])

const NOTICE = `
::: info 这一页是仓库里的设计说明原文
由构建脚本从 [\`docs/DESIGN.md\`](${blob('docs/DESIGN.md')}) 引入,**不重写、不节选**。

要改它,改仓库里那一份 —— 这一页下次构建就跟上。
:::
`

let text = readFileSync(source, 'utf8')

for (const { pattern, to } of REWRITES) {
  text = text.replace(pattern, to)
}

// 兜底:任何还活着的、指向仓库文件的相对链接,一律当成"映射没盖住"。
// 只认 `.md` 和带路径的源码引用,`#锚点` 和站内绝对路径不算。
const leftovers = [...text.matchAll(/\]\(([^)\s]+)\)/g)]
  .map((m) => m[1])
  .filter((href) => !/^(https?:|mailto:|#)/.test(href))
  .filter((href) => !SITE_ROUTES.has(href))

if (leftovers.length > 0) {
  console.error(
    `\n docs/DESIGN.md 里有 ${leftovers.length} 条链接没被 REWRITES 盖住:\n` +
      leftovers.map((h) => `   ${h}`).join('\n') +
      `\n\n要么在 site/scripts/build-design.mjs 的 REWRITES 里加一条,` +
      `要么把它做成站内页面。\n`,
  )
  process.exit(1)
}

// 标题必须是第一行 —— 下面的插入靠它定位,挪了位置就该报错,不该猜。
const lines = text.split('\n')
const titleAt = lines.findIndex((l) => l.startsWith('# '))
if (titleAt === -1) {
  console.error('\n docs/DESIGN.md 找不到一级标题。\n')
  process.exit(1)
}

lines.splice(titleAt + 1, 0, NOTICE.trimEnd())

const frontmatter = [
  '---',
  'editLink: false', // 这一页是生成的,仓库里没有对应的可编辑文件
  'lastUpdated: false', // 同上:它没有 git 历史
  '---',
  '',
].join('\n')

mkdirSync(dirname(fileURLToPath(target)), { recursive: true })
writeFileSync(target, frontmatter + lines.join('\n'))

console.log(`design/index.md ← docs/DESIGN.md(${lines.length} 行,链接来自 ${REPO})`)
