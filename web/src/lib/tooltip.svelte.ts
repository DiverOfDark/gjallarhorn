// One shared tooltip that follows the pointer.
export const tip = $state({ text: '', x: 0, y: 0, show: false })

export function tooltip(node: HTMLElement, text: string) {
  let current = text
  const move = (e: PointerEvent) => {
    tip.x = e.clientX
    tip.y = e.clientY
  }
  const enter = (e: PointerEvent) => {
    tip.text = current
    tip.show = true
    move(e)
  }
  const leave = () => (tip.show = false)
  node.addEventListener('pointerenter', enter)
  node.addEventListener('pointermove', move)
  node.addEventListener('pointerleave', leave)
  return {
    update(t: string) {
      current = t
      if (tip.show) tip.text = t
    },
    destroy() {
      node.removeEventListener('pointerenter', enter)
      node.removeEventListener('pointermove', move)
      node.removeEventListener('pointerleave', leave)
      tip.show = false
    },
  }
}
