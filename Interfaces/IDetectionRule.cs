using WinEDR_MVP.Models;
using System.Collections.Generic;

namespace WinEDR_MVP.Interfaces
{
    public interface IDetectionRule
    {
        string RuleId { get; }
        string Name { get; }
        string Description { get; }
        int ItemsChecked { get; }
        
        // Returns a list of detection events found during this evaluation cycle
        List<DetectionEvent> Evaluate();
    }
}
