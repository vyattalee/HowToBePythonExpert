import datetime
import backtrader as bt

class WaveTrendStrategy(bt.Strategy):

    def log(self, txt, dt=None):
        """ Logging function fot this strategy"""
        dt = dt or self.data.datetime[0]
        if isinstance(dt, float):
            dt = bt.num2date(dt)
        print("%s, %s" % (dt.date(), txt))

    def print_signal(self):
        self.log(
            f"o {self.datas[0].open[0]:7.2f} "
            f"h {self.datas[0].high[0]:7.2f} "
            f"l {self.datas[0].low[0]:7.2f} "
            f"c {self.datas[0].close[0]:7.2f} "
            f"v {self.datas[0].volume[0]:7.0f} "
            # f"rsi {self.rsi[0]:5.0f}"
        )

    def notify_order(self, order):
        """ Triggered upon changes to orders. """

        # Suppress notification if it is just a submitted order.
        if order.status == order.Submitted:
            return

        # Print out the date, security name, order number and status.
        dt, dn = self.datetime.date(), order.data._name
        type = "Buy" if order.isbuy() else "Sell"
        self.log(
            f"{order.data._name:<6} Order: {order.ref:3d}\tType: {type:<5}\tStatus"
            f" {order.getstatusname():<8} \t"
            f"Size: {order.created.size:9.4f} Price: {order.created.price:9.4f} "
            f"Position: {self.getposition(order.data).size}"
        )
        if order.status == order.Margin:
            return

        # Check if an order has been completed
        if order.status in [order.Completed]:
            self.log(
                f"{order.data._name:<6} {('BUY' if order.isbuy() else 'SELL'):<5} "
                # f"EXECUTED for: {dn} "
                f"Price: {order.executed.price:6.2f} "
                f"Cost: {order.executed.value:6.2f} "
                f"Comm: {order.executed.comm:4.2f} "
                f"Size: {order.created.size:9.4f} "
            )

    def notify_trade(self, trade):
        """Provides notification of closed trades."""
        if trade.isclosed:
            self.log(
                "{} Closed: PnL Gross {}, Net {},".format(
                    trade.data._name,
                    round(trade.pnl, 2),
                    round(trade.pnlcomm, 1),
                )
            )

    def __init__(self):
        n1 = 21
        n2 = 14
        obLevel1 = 60
        obLevel1 = 60
        obLevel2 = 53
        osLevel1 = -60
        osLevel2 = -53
        hlc3 = (self.data.high + self.data.low + self.data.close) / 3
        ap = hlc3
        esa = bt.ind.EMA(ap, period=n1)
        d = bt.ind.EMA(abs(ap - esa), period=n1)
        ci = (ap - esa) / (0.015 * d)
        tci = bt.ind.EMA(ci, period=n2)
        wt1 = tci
        wt2 = bt.ind.SMA(wt1, period=4)
        self.longCondition = bt.ind.CrossUp(wt2, osLevel2)
        self.shortCondition = bt.ind.CrossDown(wt2, obLevel2)

    def next(self):
        # Print OHLCV
        self.print_signal()

        if self.longCondition:
            if self.getposition().size != 0:
                self.close()
            self.buy()

        elif self.shortCondition:
            if self.getposition().size != 0:
                self.close()
            self.sell()



if __name__ == "__main__":

    cerebro = bt.Cerebro()

    data = bt.feeds.YahooFinanceData(
        dataname="FB",
        timeframe=bt.TimeFrame.Days,
        fromdate=datetime.datetime(2018, 1, 1),
        todate=datetime.datetime(2021, 4, 1),
        reverse=False,
    )

    cerebro.adddata(data, name="FB")

    cerebro.addstrategy(WaveTrendStrategy)

    # Execute
    cerebro.run()
    print(f"Final Value: {cerebro.broker.getvalue():5.2f}")

    cerebro.plot()