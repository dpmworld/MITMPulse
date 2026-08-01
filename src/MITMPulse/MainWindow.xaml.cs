using Elem = Wpf.Ui.Controls;

namespace MITMPulse;

public partial class MainWindow : Elem.FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.ViewModel;
    }
}