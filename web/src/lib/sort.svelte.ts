/** Column sort state for a table. `key` returns a number or string. */
export class Sorter<T> {
  col = $state('')
  desc = $state(true)
  constructor(
    private keys: Record<string, (r: T) => number | string>,
    initial: string,
    desc = true,
  ) {
    this.col = initial
    this.desc = desc
  }
  toggle(col: string) {
    if (this.col === col) this.desc = !this.desc
    else {
      this.col = col
      this.desc = true
    }
  }
  arrow(col: string) {
    return this.col === col ? (this.desc ? ' ↓' : ' ↑') : ''
  }
  apply(rows: T[]): T[] {
    const k = this.keys[this.col]
    if (!k) return rows
    const d = this.desc ? -1 : 1
    return [...rows].sort((a, b) => {
      const x = k(a)
      const y = k(b)
      return (x < y ? -1 : x > y ? 1 : 0) * d
    })
  }
}
