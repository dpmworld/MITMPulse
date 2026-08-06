using Elem = Wpf.Ui.Controls;

namespace MITMPulse;

public partial class MainWindow : Elem.FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.ViewModel;
        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, System.Windows.RoutedEventArgs e)
    {
        App.ViewModel?.CheckFirstLaunchDisclaimer();
    }
}