using Elem = Wpf.Ui.Controls;

namespace MITMPulse;

public partial class MainWindow : Elem.FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.ViewModel;
        Loaded += MainWindow_Loaded;
        MouseDown += MainWindow_MouseDown;
        AppTitleBar.MouseLeftButtonDown += (s, e) =>
        {
            if (e.LeftButton == System.Windows.Input.MouseButtonState.Pressed)
            {
                DragMove();
            }
        };
    }

    private void MainWindow_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.ChangedButton == System.Windows.Input.MouseButton.Left && e.GetPosition(this).Y < 40)
        {
            DragMove();
        }
    }

    private void MainWindow_Loaded(object sender, System.Windows.RoutedEventArgs e)
    {
        App.ViewModel?.CheckFirstLaunchDisclaimer();
    }
}