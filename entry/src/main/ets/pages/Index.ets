@Entry
@Component
struct Index {
  build() {
    Column() {
      Text('MyApp')
        .fontSize(20)
        .fontWeight(FontWeight.Medium)
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
  }
}
