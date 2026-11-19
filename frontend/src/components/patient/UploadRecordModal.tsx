import React, { useState } from 'react';
import { 
  X, 
  UploadCloud, 
  Lock, 
  FileText, 
  AlertCircle, 
  CheckCircle2, 
  Pill, 
  Stethoscope, 
  Trash2,
  Loader2
} from 'lucide-react';
import type { RecordType, MedicalRecord } from '../../types';
import { apiService } from '../../services/api';

interface UploadRecordModalProps {
  isOpen: boolean;
  onClose: () => void;
  patientId: string;
  patientName?: string;
  onRecordUploaded: (newRecord: MedicalRecord) => void;
}

export const UploadRecordModal: React.FC<UploadRecordModalProps> = ({
  isOpen,
  onClose,
  patientId,
  patientName,
  onRecordUploaded,
}) => {
  const [title, setTitle] = useState('');
  const [recordType, setRecordType] = useState<RecordType>('LAB_REPORT');
  const [hospital, setHospital] = useState('Metro General Hospital');
  
  // Multi-input clinical fields
  const [description, setDescription] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [prescriptionFile, setPrescriptionFile] = useState<File | null>(null);

  // Status and submission states
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [uploadPhase, setUploadPhase] = useState<'idle' | 'encrypting' | 'pinning' | 'committing'>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleReset = () => {
    setTitle('');
    setRecordType('LAB_REPORT');
    setHospital('Metro General Hospital');
    setDescription('');
    setFile(null);
    setPrescriptionFile(null);
    setErrorMessage(null);
    setSuccessMessage(null);
    setUploadPhase('idle');
  };

  const handleClose = () => {
    if (isSubmitting) return;
    handleReset();
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    // 1. Mandatory title validation
    if (!title.trim()) {
      setErrorMessage('Please provide a descriptive record title.');
      return;
    }

    // 2. Multi-input validation: at least one of (description, document file, prescription file) must be supplied
    const hasDescription = Boolean(description && description.trim().length > 0);
    const hasDocument = Boolean(file);
    const hasPrescription = Boolean(prescriptionFile);

    if (!hasDescription && !hasDocument && !hasPrescription) {
      setErrorMessage(
        'Multi-input validation requirement: Please provide at least one clinical input: a clinical/symptom description, a medical document report, or a prescription attachment.'
      );
      return;
    }

    setIsSubmitting(true);
    setUploadPhase('encrypting');

    try {
      // Transition progress phase for responsive user feedback
      setTimeout(() => {
        setUploadPhase((prev) => (prev === 'encrypting' ? 'pinning' : prev));
      }, 700);

      setTimeout(() => {
        setUploadPhase((prev) => (prev === 'pinning' ? 'committing' : prev));
      }, 1500);

      const res = await apiService.uploadRecord({
        patientId,
        patientName,
        title: title.trim(),
        recordType,
        hospital: hospital.trim(),
        file: file || null,
        description: hasDescription ? description.trim() : null,
        prescriptionFile: prescriptionFile || null,
      });

      if (res.success && res.record) {
        setUploadPhase('committing');
        setSuccessMessage('Medical record encrypted with AES-256-GCM and registered on Fabric ledger & IPFS.');
        onRecordUploaded(res.record);
        setTimeout(() => {
          handleReset();
          onClose();
        }, 1300);
      } else {
        // Strict integrity: show exact error returned by backend (e.g. HTTP 422)
        setErrorMessage(
          res.error || 
          'Backend IPFS/Fabric service rejected record submission. Verify that all required fields are valid.'
        );
        setUploadPhase('idle');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error during record upload';
      setErrorMessage(`Upload submission failed: ${msg}`);
      setUploadPhase('idle');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl max-w-xl w-full border border-slate-200 shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 max-h-[90vh] flex flex-col">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 bg-slate-50/50 shrink-0">
          <div className="flex items-center space-x-2.5">
            <div className="p-2 bg-[#147D78]/10 text-[#147D78] rounded-lg border border-[#147D78]/20">
              <UploadCloud className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900">Upload Medical Record</h2>
              <p className="text-xs text-slate-500">Multi-input clinical submission with AES-256 client encryption</p>
            </div>
          </div>
          <button 
            onClick={handleClose}
            disabled={isSubmitting}
            className="text-slate-400 hover:text-slate-600 rounded-lg p-1.5 transition-colors cursor-pointer disabled:opacity-40"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body - Scrollable */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4.5 overflow-y-auto flex-1 text-xs">
          
          {/* Multi-Input Requirement Notice */}
          <div className="p-3 rounded-xl bg-slate-50 border border-slate-200 flex items-start space-x-2.5 text-slate-700">
            <Stethoscope className="w-4 h-4 text-[#147D78] shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <p className="font-semibold text-slate-900">Flexible Clinical Submission</p>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                Provide at least <strong>one</strong> of: a clinical symptom description, an encrypted document report, or a prescription attachment.
              </p>
            </div>
          </div>

          {/* Record Title */}
          <div className="space-y-1">
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
              Record Title <span className="text-rose-500">*</span>
            </label>
            <input
              type="text"
              required
              placeholder="e.g., Annual Echocardiogram Diagnostic Report & Prescriptions"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full text-xs px-3.5 py-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#147D78]/30 focus:border-[#147D78] transition-all bg-white text-slate-900"
            />
          </div>

          {/* Record Type & Clinic */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            <div className="space-y-1">
              <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
                Record Category
              </label>
              <select
                value={recordType}
                onChange={(e) => setRecordType(e.target.value as RecordType)}
                className="w-full text-xs px-3 py-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#147D78]/30 bg-white text-slate-900"
              >
                <option value="LAB_REPORT">Lab Diagnostic Report</option>
                <option value="PRESCRIPTION">Prescription / Medication</option>
                <option value="IMAGING_MRI">MRI / CT Scan Diagnostic</option>
                <option value="IMAGING_XRAY">X-Ray Imaging</option>
                <option value="CLINICAL_SUMMARY">Clinical Discharge Summary</option>
                <option value="GENOMIC_DATA">Genomic Sequencing Panel</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
                Issuing Hospital / Facility <span className="text-rose-500">*</span>
              </label>
              <input
                type="text"
                required
                value={hospital}
                onChange={(e) => setHospital(e.target.value)}
                className="w-full text-xs px-3.5 py-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#147D78]/30 bg-white text-slate-900"
              />
            </div>
          </div>

          {/* Input 1: Clinical / Symptom Description (Optional) */}
          <div className="space-y-1 pt-1">
            <div className="flex items-center justify-between">
              <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
                Clinical Notes / Symptoms Description (Optional)
              </label>
              <span className="text-[10px] text-slate-400">Zero-PHI off-chain store</span>
            </div>
            <textarea
              rows={3}
              placeholder="e.g., Patient presented with mild exertional dyspnea. Vital signs stable, BP 122/78 mmHg. Recommended low-sodium diet and titration of ACE inhibitor."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full text-xs px-3.5 py-2 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-[#147D78]/30 focus:border-[#147D78] transition-all bg-white text-slate-900 placeholder:text-slate-400"
            />
          </div>

          {/* Input 2: Medical Report Document File (Optional) */}
          <div className="space-y-1 pt-1">
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
              Medical Report Document File (Optional)
            </label>
            <div className="border border-dashed border-slate-300 rounded-xl p-3 bg-slate-50/70 hover:border-[#147D78] transition-colors">
              {file ? (
                <div className="flex items-center justify-between bg-white p-2.5 rounded-lg border border-slate-200">
                  <div className="flex items-center space-x-2.5 truncate">
                    <FileText className="w-4 h-4 text-[#147D78] shrink-0" />
                    <div className="truncate">
                      <p className="text-xs font-semibold text-slate-800 truncate">{file.name}</p>
                      <p className="text-[10px] text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB • {file.type || 'Document'}</p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setFile(null)}
                    className="p-1 text-slate-400 hover:text-rose-600 transition-colors cursor-pointer"
                    title="Remove file"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <div className="text-center py-2">
                  <FileText className="mx-auto h-6 w-6 text-slate-400 mb-1" />
                  <label className="cursor-pointer font-semibold text-[#147D78] hover:underline">
                    <span>Select medical report</span>
                    <input
                      type="file"
                      className="sr-only"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setFile(e.target.files[0]);
                        }
                      }}
                      accept=".pdf,.png,.jpg,.jpeg,.dcm,.txt"
                    />
                  </label>
                  <p className="text-[10px] text-slate-400 mt-0.5">PDF, PNG, JPG, DICOM (up to 25MB)</p>
                </div>
              )}
            </div>
          </div>

          {/* Input 3: Prescription File Attachment Picker (Optional) */}
          <div className="space-y-1 pt-1">
            <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
              Prescription File Attachment (Optional)
            </label>
            <div className="border border-dashed border-slate-300 rounded-xl p-3 bg-slate-50/70 hover:border-teal-600 transition-colors">
              {prescriptionFile ? (
                <div className="flex items-center justify-between bg-white p-2.5 rounded-lg border border-teal-200">
                  <div className="flex items-center space-x-2.5 truncate">
                    <Pill className="w-4 h-4 text-teal-600 shrink-0" />
                    <div className="truncate">
                      <p className="text-xs font-semibold text-slate-800 truncate">{prescriptionFile.name}</p>
                      <p className="text-[10px] text-slate-500">{(prescriptionFile.size / 1024).toFixed(1)} KB • Prescription Attachment</p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setPrescriptionFile(null)}
                    className="p-1 text-slate-400 hover:text-rose-600 transition-colors cursor-pointer"
                    title="Remove prescription"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <div className="text-center py-2">
                  <Pill className="mx-auto h-6 w-6 text-teal-500 mb-1" />
                  <label className="cursor-pointer font-semibold text-teal-700 hover:underline">
                    <span>Attach prescription document</span>
                    <input
                      type="file"
                      className="sr-only"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setPrescriptionFile(e.target.files[0]);
                        }
                      }}
                      accept=".pdf,.png,.jpg,.jpeg,.txt"
                    />
                  </label>
                  <p className="text-[10px] text-slate-400 mt-0.5">Digital prescription (PDF, Image, Text)</p>
                </div>
              )}
            </div>
          </div>

          {/* Security Protocol Notice */}
          <div className="flex items-start space-x-2.5 p-3 rounded-lg bg-[#14263D]/5 border border-[#14263D]/10 text-xs text-[#14263D]">
            <Lock className="w-4 h-4 text-[#147D78] shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong>Security Invariant:</strong> Payloads are encrypted client-side using ephemeral AES-256-GCM. Ciphertext is pinned to IPFS Kubo and registered with an immutable SHA-256 checksum on the Fabric ledger.
            </p>
          </div>

          {/* Responsive Progress State */}
          {isSubmitting && (
            <div className="p-3.5 rounded-xl bg-teal-50 border border-teal-200 text-teal-900 space-y-2">
              <div className="flex items-center space-x-2 font-semibold">
                <Loader2 className="w-4 h-4 animate-spin text-[#147D78]" />
                <span>
                  {uploadPhase === 'encrypting' && 'Encrypting clinical payload (AES-256-GCM)...'}
                  {uploadPhase === 'pinning' && 'Pinning encrypted ciphertext to IPFS Kubo...'}
                  {uploadPhase === 'committing' && 'Committing record metadata to Fabric ledger...'}
                  {uploadPhase === 'idle' && 'Processing submission...'}
                </span>
              </div>
              <div className="w-full bg-teal-200 rounded-full h-1.5 overflow-hidden">
                <div 
                  className="bg-[#147D78] h-1.5 transition-all duration-500 rounded-full"
                  style={{
                    width: uploadPhase === 'encrypting' ? '30%' : uploadPhase === 'pinning' ? '65%' : '95%'
                  }}
                />
              </div>
            </div>
          )}

          {/* Error Message (with graceful HTTP 422 display) */}
          {errorMessage && (
            <div className="flex items-start space-x-2 p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <div className="space-y-0.5">
                <p className="font-semibold text-rose-900">Upload Validation Error</p>
                <p className="leading-relaxed">{errorMessage}</p>
              </div>
            </div>
          )}

          {/* Success Message */}
          {successMessage && (
            <div className="flex items-center space-x-2 p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              <span className="font-semibold">{successMessage}</span>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex justify-end space-x-3 pt-3 border-t border-slate-100 shrink-0">
            <button
              type="button"
              onClick={handleClose}
              disabled={isSubmitting}
              className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="inline-flex items-center space-x-1.5 px-4 py-2 text-xs font-semibold text-white bg-[#147D78] hover:bg-[#116965] rounded-lg shadow-xs transition-colors disabled:opacity-60 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-white" />
                  <span>Processing Upload...</span>
                </>
              ) : (
                <>
                  <UploadCloud className="w-3.5 h-3.5" />
                  <span>Encrypt &amp; Upload Record</span>
                </>
              )}
            </button>
          </div>

        </form>

      </div>
    </div>
  );
};
