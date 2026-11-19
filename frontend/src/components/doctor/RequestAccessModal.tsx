import React, { useState } from 'react';
import { X, ShieldPlus, AlertCircle, CheckCircle2, User } from 'lucide-react';
import type { RecordType, ConsentRequestPayload } from '../../types';
import { apiService } from '../../services/api';

interface RequestAccessModalProps {
  isOpen: boolean;
  onClose: () => void;
  doctorId: string;
  defaultPatientId?: string;
  onRequestSubmitted: () => void;
}

export const RequestAccessModal: React.FC<RequestAccessModalProps> = ({
  isOpen,
  onClose,
  doctorId,
  defaultPatientId = 'pat-984210',
  onRequestSubmitted,
}) => {
  const [patientId, setPatientId] = useState(defaultPatientId);
  const [purpose, setPurpose] = useState('');
  const [durationDays, setDurationDays] = useState(30);
  const [selectedTypes, setSelectedTypes] = useState<RecordType[]>([
    'LAB_REPORT',
    'PRESCRIPTION',
    'CLINICAL_SUMMARY',
  ]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleToggleType = (type: RecordType) => {
    if (selectedTypes.includes(type)) {
      setSelectedTypes(selectedTypes.filter(t => t !== type));
    } else {
      setSelectedTypes([...selectedTypes, type]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!purpose.trim()) {
      setErrorMessage('Please state the clinical or diagnostic purpose for this request.');
      return;
    }

    if (selectedTypes.length === 0) {
      setErrorMessage('Please select at least one record category.');
      return;
    }

    setIsSubmitting(true);

    const payload: ConsentRequestPayload = {
      patientId,
      doctorId,
      purpose,
      durationDays,
      allowedRecordTypes: selectedTypes,
    };

    try {
      const res = await apiService.requestConsent(payload);
      if (res.success) {
        setSuccessMessage('Consent request successfully dispatched to patient and logged to Fabric.');
        onRequestSubmitted();
        setTimeout(() => {
          onClose();
        }, 1200);
      } else {
        setErrorMessage(res.error || 'Failed to submit request to backend Fabric service.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Error submitting request';
      setErrorMessage(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl max-w-lg w-full border border-slate-200 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 bg-slate-50/50">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-[#147D78]/10 text-[#147D78] rounded-lg border border-[#147D78]/20">
              <ShieldPlus className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">Request Record Access</h2>
              <p className="text-xs text-slate-500">Requires cryptographic authorization by the patient</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 rounded-lg p-1.5 transition-colors"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          
          {/* Patient ID */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
              Target Patient Identifier
            </label>
            <div className="relative">
              <User className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
              <input
                type="text"
                required
                value={patientId}
                onChange={(e) => setPatientId(e.target.value)}
                placeholder="e.g., pat-984210"
                className="w-full text-sm pl-9 pr-3.5 py-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-500 bg-white"
              />
            </div>
          </div>

          {/* Clinical Purpose */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
              Clinical Justification & Purpose
            </label>
            <textarea
              required
              rows={3}
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              placeholder="e.g., Pre-operative cardiovascular clearance and assessment of recent lab diagnostic indicators..."
              className="w-full text-sm px-3.5 py-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-500 bg-white"
            />
          </div>

          {/* Requested Duration */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
              Requested Access Duration
            </label>
            <div className="flex items-center space-x-3">
              {[7, 14, 30, 90].map((days) => (
                <button
                  type="button"
                  key={days}
                  onClick={() => setDurationDays(days)}
                  className={`flex-1 py-2 text-xs font-semibold rounded-lg border transition-all ${
                    durationDays === days
                      ? 'bg-emerald-50 text-emerald-700 border-emerald-300 ring-2 ring-emerald-500/20'
                      : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  {days} Days
                </button>
              ))}
            </div>
          </div>

          {/* Scoped Record Types */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2">
              Requested Record Categories
            </label>
            <div className="grid grid-cols-2 gap-2 text-xs">
              {[
                { id: 'LAB_REPORT' as RecordType, label: 'Lab Reports' },
                { id: 'PRESCRIPTION' as RecordType, label: 'Prescriptions' },
                { id: 'IMAGING_MRI' as RecordType, label: 'MRI / CT Scans' },
                { id: 'IMAGING_XRAY' as RecordType, label: 'X-Ray Scans' },
                { id: 'CLINICAL_SUMMARY' as RecordType, label: 'Clinical Summaries' },
                { id: 'GENOMIC_DATA' as RecordType, label: 'Genomics' },
              ].map((item) => (
                <label 
                  key={item.id} 
                  className={`flex items-center space-x-2 p-2 rounded-lg border cursor-pointer transition-colors ${
                    selectedTypes.includes(item.id)
                      ? 'bg-emerald-50/60 border-emerald-200 text-emerald-900'
                      : 'bg-white border-slate-200 text-slate-600 hover:bg-slate-50'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={selectedTypes.includes(item.id)}
                    onChange={() => handleToggleType(item.id)}
                    className="rounded text-emerald-600 focus:ring-emerald-500"
                  />
                  <span>{item.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Feedback messages */}
          {errorMessage && (
            <div className="flex items-start space-x-2 p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-700">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="flex items-center space-x-2 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-700">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex justify-end space-x-3 pt-3 border-t border-slate-100">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="inline-flex items-center space-x-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#147D78] hover:bg-[#116965] rounded-lg shadow-xs transition-colors disabled:opacity-60"
            >
              {isSubmitting ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  <span>Submitting...</span>
                </>
              ) : (
                <>
                  <ShieldPlus className="w-3.5 h-3.5" />
                  <span>Transmit Access Request</span>
                </>
              )}
            </button>
          </div>

        </form>

      </div>
    </div>
  );
};
