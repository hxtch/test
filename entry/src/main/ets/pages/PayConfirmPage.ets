import router from '@ohos.router';
import hilog from '@ohos.hilog';
import common from '@ohos.app.ability.common';
import Want from '@ohos.app.ability.Want';

const TAG = 'PayConfirmPage';
const DOMAIN = 0x0000;

interface PayParams {
  orderId: string;
  callbackUrl: string;
}

@Entry
@Component
struct PayConfirmPage {
  @State orderId: string = '';
  @State callbackUrl: string = '';
  @State orderAmount: string = '--';
  @State loading: boolean = true;
  @State paymentProcessing: boolean = false;

  aboutToAppear(): void {
    const params = router.getParams() as PayParams;
    if (params) {
      this.orderId = params.orderId ?? '';
      this.callbackUrl = params.callbackUrl ?? '';
    }

    if (!this.orderId) {
      hilog.error(DOMAIN, TAG, 'No orderId provided');
      this.terminateSelf();
      return;
    }

    this.fetchOrderInfo();
  }

  private fetchOrderInfo(): void {
    // TODO: Replace with actual backend API call to verify order server-side
    hilog.info(DOMAIN, TAG, 'Fetching order info for: %{public}s', this.orderId);
    setTimeout(() => {
      this.orderAmount = '¥99.00';
      this.loading = false;
    }, 500);
  }

  private terminateSelf(): void {
    const context = getContext(this) as common.UIAbilityContext;
    context.terminateSelf();
  }

  private async onConfirmPayment(): Promise<void> {
    if (this.paymentProcessing) return;
    this.paymentProcessing = true;
    hilog.info(DOMAIN, TAG, 'Payment confirmed for orderId: %{public}s', this.orderId);

    // TODO: Replace with actual payment execution logic
    try {
      await this.invokeCallback('success');
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'Payment failed: %{public}s', String(e));
      this.paymentProcessing = false;
    }
  }

  private async invokeCallback(result: string): Promise<void> {
    if (!this.callbackUrl) {
      this.terminateSelf();
      return;
    }

    const context = getContext(this) as common.UIAbilityContext;
    const want: Want = {
      action: 'ohos.want.action.viewData',
      entities: ['entity.system.browsable'],
      uri: `${this.callbackUrl}?orderId=${this.orderId}&result=${result}`
    };

    try {
      await context.startAbility(want);
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'Callback invocation failed: %{public}s', String(e));
    }
    this.terminateSelf();
  }

  build() {
    Column() {
      Text('Payment Confirmation')
        .fontSize(22)
        .fontWeight(FontWeight.Bold)
        .margin({ top: 60, bottom: 30 })

      if (this.loading) {
        LoadingProgress()
          .width(48)
          .height(48)
          .margin({ top: 80 })
      } else {
        Column() {
          Row() {
            Text('Order ID:')
              .fontSize(16)
              .fontColor('#666')
            Text(this.orderId)
              .fontSize(16)
              .fontWeight(FontWeight.Medium)
              .margin({ left: 8 })
          }
          .width('100%')
          .justifyContent(FlexAlign.SpaceBetween)
          .padding({ left: 20, right: 20 })
          .margin({ top: 20 })

          Row() {
            Text('Amount:')
              .fontSize(16)
              .fontColor('#666')
            Text(this.orderAmount)
              .fontSize(24)
              .fontWeight(FontWeight.Bold)
              .fontColor('#E64340')
              .margin({ left: 8 })
          }
          .width('100%')
          .justifyContent(FlexAlign.SpaceBetween)
          .padding({ left: 20, right: 20 })
          .margin({ top: 16 })
        }
        .width('90%')
        .backgroundColor('#FFFFFF')
        .borderRadius(12)
        .padding(20)
        .margin({ top: 30 })

        Button(this.paymentProcessing ? 'Processing...' : 'Confirm Payment')
          .width('90%')
          .height(48)
          .fontSize(18)
          .fontColor('#FFFFFF')
          .backgroundColor(this.paymentProcessing ? '#CCCCCC' : '#07C160')
          .borderRadius(24)
          .margin({ top: 40 })
          .enabled(!this.paymentProcessing)
          .onClick(() => this.onConfirmPayment())

        Button('Cancel')
          .width('90%')
          .height(48)
          .fontSize(18)
          .fontColor('#666666')
          .backgroundColor('#F5F5F5')
          .borderRadius(24)
          .margin({ top: 16 })
          .onClick(() => this.terminateSelf())
      }
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#F5F5F5')
    .alignItems(HorizontalAlign.Center)
  }
}
