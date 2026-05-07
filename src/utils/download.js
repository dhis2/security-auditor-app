// Trigger a browser download for an in-memory Blob. Used by the audit-report
// exporter (HTML) and the configuration exporter (JSON).
export const downloadBlob = (blob, filename) => {
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
}
