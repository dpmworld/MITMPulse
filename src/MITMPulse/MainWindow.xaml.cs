using Elem = Wpf.Ui.Controls;

namespace MITMPulse;

public partial class MainWindow : Elem.FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.ViewModel;
        Loaded += MainWindow_Loaded;
        AppTitleBar.MouseLeftButtonDown += (s, e) =>
        {
            if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed)
            {
                try
                {
                    DragMove();
                }
                catch (System.InvalidOperationException)
                {
                    // Ignore transient mouse release/double-click race conditions
                }
            }
        };
    }

    private void MainWindow_Loaded(object sender, System.Windows.RoutedEventArgs e)
    {
        App.ViewModel?.CheckFirstLaunchDisclaimer();
    }
}