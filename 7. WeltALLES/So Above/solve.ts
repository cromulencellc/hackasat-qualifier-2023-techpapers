// deno-lint-ignore-file prefer-const
import iced from "npm:iced-x86@1.18.0"
import elfinfo from "npm:elfinfo@0.4.0-beta"
import { Buffer } from 'node:buffer';

const file_data = await Deno.readFile("/chall/challs/generated") // Deno.readFile("generated")
const info = await elfinfo.open(file_data)
const qmSymbol = info.elf.sections.filter(x => x.name == ".symtab")[0].symbols.filter(x => x.name == "quick_maths")[0]

function getBytes(addr, len) {
  return file_data.slice(addr, addr + len)
}

let funcData = file_data.slice(parseInt(qmSymbol.value), parseInt(qmSymbol.value) + qmSymbol.size)
let decoder = new iced.Decoder(64, funcData)
decoder.ip = qmSymbol.value

let instructions = decoder.decodeAll()
let formatter = new iced.Formatter()

let parsed: any[] = []
for (let i = 2; i < instructions.length - 11; i += 4) {
  let dataAddr = formatter.format(instructions[i + 2]).split(" ")[1].split(",")[0]
  let data = getBytes(Number(dataAddr), 8)

  parsed.push([
    (new Buffer(data)).readDoubleLE(),
    formatter.format(instructions[i + 3]).split(" ")[0]
  ])
}

let targetAddr = formatter.format(instructions[instructions.length - 4]).split(" ")[1].split(",")[0]
let target = (new Buffer(getBytes(Number(targetAddr), 8))).readDoubleLE()

// console.log(parsed)
// console.log(target)

parsed.reverse().forEach(e => {
  switch (e[1]) {
    case "addsd":
      target -= e[0]
      break;

    case "subsd":
      target += e[0]
      break;

    case "divsd":
      target *= e[0]
      break;

    default:
      throw ":("
  }
})
console.log(BigInt(target))
